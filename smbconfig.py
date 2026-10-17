"""Loss-minimizing editor for the direct sections of smb.conf.

It does not attempt to expand Samba include files or resolve parameter aliases.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

SECTION = re.compile(r'^\s*\[([^\]\r\n]+)\]\s*(?:[#;].*)?$', re.I)
OPTION = re.compile(r'^\s*([^#;\s][^=]*?)\s*=\s*(.*?)\s*$', re.I)


def canonical(value: str) -> str:
    return re.sub(r'\s+', ' ', value.strip().lower().replace('_', ' '))


@dataclass
class Block:
    name: str
    begin: int
    end: int


class SmbConf:
    def __init__(self, content: str):
        self.content = content

    def checksum(self) -> str:
        return hashlib.sha256(self.content.encode('utf-8')).hexdigest()

    def _lines(self) -> list[str]:
        return self.content.splitlines(keepends=True)

    def blocks(self) -> list[Block]:
        lines = self._lines()
        starts = []
        for i, line in enumerate(lines):
            match = SECTION.match(line.rstrip('\r\n'))
            if match:
                starts.append((i, match.group(1).strip()))
        return [Block(name, start, starts[n + 1][0] if n + 1 < len(starts) else len(lines))
                for n, (start, name) in enumerate(starts)]

    def sections(self) -> list[str]:
        return [b.name for b in self.blocks()]

    def _block(self, name: str) -> Block | None:
        found = [b for b in self.blocks() if b.name.casefold() == name.casefold()]
        if len(found) > 1:
            raise ValueError(f'Multiple [{name}] sections: cannot safely edit')
        return found[0] if found else None

    def options(self, name: str) -> dict[str, str]:
        block = self._block(name)
        if block is None:
            return {}
        options = {}
        for line in self._lines()[block.begin + 1:block.end]:
            m = OPTION.match(line.rstrip('\r\n'))
            if m:
                options[canonical(m.group(1))] = m.group(2).strip()
        return options

    def update(self, name: str, updates: dict[str, str | None], create: bool = False) -> 'SmbConf':
        """Replace only explicitly submitted keys, leaving other lines alone."""
        existing = self._block(name)
        if create and existing:
            raise ValueError(f'[{name}] already exists')
        if not create and existing is None and name.casefold() != 'global':
            raise ValueError(f'[{name}] does not exist')
        normalized = {canonical(k): v for k, v in updates.items()}
        for value in normalized.values():
            if value is not None and ('\n' in value or '\r' in value):
                raise ValueError('Newlines are not allowed in config values')
        lines = self._lines()
        if existing is None:
            if name.casefold() == 'global':
                additions = ['[global]\n'] + [f'    {k} = {v}\n' for k, v in normalized.items() if v is not None]
                return SmbConf(''.join(additions) + '\n' + self.content)
            addition = '\n' if self.content and not self.content.endswith('\n') else ''
            addition += f'\n[{name}]\n'
            addition += ''.join(f'    {k} = {v}\n' for k, v in normalized.items() if v is not None)
            return SmbConf(self.content + addition)

        pre = lines[:existing.begin + 1]
        body = []
        used = set()
        for line in lines[existing.begin + 1:existing.end]:
            m = OPTION.match(line.rstrip('\r\n'))
            if m and (key := canonical(m.group(1))) in normalized:
                if key not in used and normalized[key] is not None:
                    body.append(f'    {key} = {normalized[key]}\n')
                used.add(key)
            else:
                body.append(line)
        for key, value in normalized.items():
            if key not in used and value is not None:
                # Insert before trailing blank lines/comments, preserving the other content.
                end = len(body)
                while end and not body[end - 1].strip():
                    end -= 1
                if end and not body[end - 1].endswith(('\n', '\r')):
                    body[end - 1] += '\n'
                body.insert(end, f'    {key} = {value}\n')
        # If the original section lacked a final newline, preserve valid line breaks.
        if body and not body[-1].endswith(('\n', '\r')) and existing.end < len(lines):
            body[-1] += '\n'
        return SmbConf(''.join(pre + body + lines[existing.end:]))

    def delete(self, name: str) -> 'SmbConf':
        b = self._block(name)
        if b is None or name.casefold() == 'global':
            raise ValueError('Share not found or protected')
        lines = self._lines()
        # Only remove the section itself; adjacent comments before it remain.
        return SmbConf(''.join(lines[:b.begin] + lines[b.end:]))
