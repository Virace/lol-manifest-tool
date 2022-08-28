# -*- coding: utf-8 -*-
# @Author  : Virace
# @Email   : Virace@aliyun.com
# @Site    : x-item.com
# @Software: Pycharm
# @Create  : 2022/8/28 21:47
# @Update  : 2022/8/28 21:47
# @Detail  : Thanks to CDTB: https://github.com/CommunityDragon/CDTB
import hashlib
import io
import os
from dataclasses import dataclass
from typing import Dict, Union

import requests
import zstd
from loguru import logger

from lol_manifest.tools import BinaryParser, write_file_or_remove


@dataclass(frozen=True)
class ReleaseInfo:
    version: str = ''
    sub: str = ''
    url: str = ''


class Release:
    """
    版本获取, manifes只获取资源文件, lol-standalone-client-content
    不包含可执行文件exe, dll等
    """
    client: ReleaseInfo
    game: ReleaseInfo

    def __init__(self, patchline='live', region=('EUW', 'EUW1')):
        """
        用来处理游戏版本相关数据
        :param patchline: live 正式服、 pbe 体验服
        :param region: 地区(client, game), 全大写
        """
        self._patchline = patchline
        self._client_region, self._game_region = region
        self._get = requests.get

    def fetch_latest_info(self):
        cv = self.get_latest_client_manifest()
        gv = self.get_latest_game_manifest()
        self.client = ReleaseInfo(version=cv[0], url=cv[1])
        self.game = ReleaseInfo(version=gv[0], sub=gv[1], url=gv[2])

    def get_latest_client_manifest(self) -> tuple:
        """
        获取客户端最新版本号
        :return: 版本，清单连接
        """
        r = self._get(
            f"https://clientconfig.rpg.riotgames.com/api/v1/config/public?namespace=keystone.products.league_of_legends.patchlines")
        r.raise_for_status()
        data = r.json()
        region = 'PBE' if self._patchline.lower() == 'pbe' else self._client_region

        for config in data[f"keystone.products.league_of_legends.patchlines.{self._patchline}"]["platforms"]["win"][
            "configurations"]:
            if config['id'] == region:
                theme_manifest = config['metadata']['theme_manifest']
                version = os.path.basename(os.path.dirname(os.path.dirname(theme_manifest)))
                return version, config['patch_url']
        raise ValueError(f"client configuration not found for {self._patchline}")

    def get_latest_game_manifest(self) -> tuple:
        """
        获取游戏最新版本号
        :return: 大版本, 小版本, 清单连接
        """
        platform = 'PBE1' if self._patchline.lower() == 'pbe' else self._game_region
        # https://sieve.services.riotcdn.net/api/v1/products/lol/version-sets/PBE1?q[platform]=windows
        r = self._get(
            f"https://sieve.services.riotcdn.net/api/v1/products/lol/version-sets/{platform}?q[platform]=windows&q[published]=true")
        r.raise_for_status()
        data = r.json()
        assert len(data["releases"]) == 1
        this = data["releases"][-1]
        url = this["download"]["url"]

        version = this["release"]["labels"]["riot:artifact_version_id"]["values"][0].split("+")[0].split('.')
        sv = '.'.join(version[:2])
        return sv, version[-1], url


class PatcherBundle:
    def __init__(self, bundle_id):
        self.bundle_id = bundle_id
        self.chunks = []

    def add_chunk(self, chunk_id, size, target_size):
        try:
            last_chunk = self.chunks[-1]
            offset = last_chunk.offset + last_chunk.size
        except IndexError:
            offset = 0
        self.chunks.append(PatcherChunk(chunk_id, self, offset, size, target_size))


@dataclass
class PatcherChunk:
    chunk_id: int
    bundle: PatcherBundle
    offset: int
    size: int
    target_size: int


class PatcherFile:
    def __init__(self, name, size, link, flags, chunks):
        self.name = name
        self.size = size
        self.link = link
        self.flags = flags
        self.chunks = chunks

    def hexdigest(self):
        """Compute a hash unique for this file content"""
        m = hashlib.sha1()
        for chunk in self.chunks:
            m.update(b"%016X" % chunk.chunk_id)
        return m.hexdigest()

    @staticmethod
    def langs_predicate(langs):
        """Return a predicate function for a locale filtering parameter"""
        if langs is False:
            # assume only locales flags follow this pattern
            return lambda f: f.flags is None or not any('_' in f and len(f) == 5 for f in f.flags)
        elif langs is True:
            return lambda f: True
        else:
            lang = langs.lower()  # compare lowercased
            return lambda f: f.flags is not None and any(f.lower() == lang for f in f.flags)

    def __repr__(self):
        return f'{self.name}, size:{self.size}, chunks:{len(self.chunks)}, flags:{self.flags}'


class Manifest:
    def __init__(self, file: Union[str, os.PathLike]):
        self.bundles: list = []
        self.chunks: dict = {}
        self.flags: Dict[str, PatcherFile] = {}
        self.files: dict = {}

        logger.debug('Manifest file: {}', file)
        if isinstance(file, str):
            if '://' in file:
                res = requests.get(file)
                res.raise_for_status()
                self.parse_rman(io.BytesIO(res.content))
            else:
                with open(file, "rb") as f:
                    self.parse_rman(f)
        else:
            with open(file, "rb") as f:
                self.parse_rman(f)

    def filter_files(self, langs=True):
        """Filter files from the manifest with provided filters"""
        return filter(PatcherFile.langs_predicate(langs), self.files.values())

    def parse_rman(self, f):
        parser = BinaryParser(f)

        magic, version_major, version_minor = parser.unpack("<4sBB")
        if magic != b'RMAN':
            raise ValueError("invalid magic code")
        if (version_major, version_minor) != (2, 0):
            raise ValueError(f"unsupported RMAN version: {version_major}.{version_minor}")

        flags, offset, length, _manifest_id, _body_length = parser.unpack("<HLLQL")
        assert flags & (1 << 9)  # other flags not handled
        assert offset == parser.tell()

        f = io.BytesIO(zstd.decompress(parser.raw(length)))
        return self.parse_body(f)

    def parse_body(self, f):
        parser = BinaryParser(f)

        # header (unknown values, skip it)
        n, = parser.unpack('<l')
        parser.skip(n)

        # offsets to tables (convert to absolute)
        offsets_base = parser.tell()
        offsets = list(offsets_base + 4 * i + v for i, v in enumerate(parser.unpack(f'<6l')))

        parser.seek(offsets[0])
        self.bundles = list(self._parse_table(parser, self._parse_bundle))

        parser.seek(offsets[1])
        self.flags = dict(self._parse_table(parser, self._parse_flag))

        # build a list of chunks, indexed by ID
        self.chunks = {chunk.chunk_id: chunk for bundle in self.bundles for chunk in bundle.chunks}

        parser.seek(offsets[2])
        file_entries = list(self._parse_table(parser, self._parse_file_entry))
        parser.seek(offsets[3])
        directories = {did: (name, parent) for name, did, parent in self._parse_table(parser, self._parse_directory)}

        # merge files and directory data
        self.files = {}
        for name, link, flag_ids, dir_id, filesize, chunk_ids in file_entries:
            while dir_id is not None:
                dir_name, dir_id = directories[dir_id]
                name = f"{dir_name}/{name}"
            if flag_ids is not None:
                flags = [self.flags[i] for i in flag_ids]
            else:
                # flags = None
                flags = []
            file_chunks = [self.chunks[chunk_id] for chunk_id in chunk_ids]
            self.files[name] = PatcherFile(name, filesize, link, flags, file_chunks)

        # note: last two tables are unresolved

    @staticmethod
    def _parse_table(parser, entry_parser):
        count, = parser.unpack('<l')

        for _ in range(count):
            pos = parser.tell()
            offset, = parser.unpack('<l')
            parser.seek(pos + offset)
            yield entry_parser(parser)
            parser.seek(pos + 4)

    @staticmethod
    def _parse_bundle(parser):
        """Parse a bundle entry"""
        _, n, bundle_id = parser.unpack('<llQ')
        # skip remaining header part, if any
        parser.skip(n - 12)

        bundle = PatcherBundle(bundle_id)
        n, = parser.unpack('<l')
        for _ in range(n):
            pos = parser.tell()
            offset, = parser.unpack('<l')
            parser.seek(pos + offset)
            parser.skip(4)  # skip offset table offset
            compressed_size, uncompressed_size, chunk_id = parser.unpack('<LLQ')
            bundle.add_chunk(chunk_id, compressed_size, uncompressed_size)
            parser.seek(pos + 4)

        return bundle

    @staticmethod
    def _parse_flag(parser):
        parser.skip(4)  # skip offset table offset
        flag_id, offset, = parser.unpack('<xxxBl')
        parser.skip(offset - 4)
        return flag_id, parser.unpack_string()

    @classmethod
    def _parse_file_entry(cls, parser):
        """Parse a file entry
        (name, link, flag_ids, directory_id, filesize, chunk_ids)
        """
        fields = cls._parse_field_table(parser, (
            None,
            ('chunks', 'offset'),
            ('file_id', '<Q'),
            ('directory_id', '<Q'),
            ('file_size', '<L'),
            ('name', 'str'),
            ('flags', '<Q'),
            None,
            None,
            None,
            None,
            ('link', 'str'),
            None,
            None,
            None,
        ))

        flag_mask = fields['flags']
        if flag_mask:
            flag_ids = [i + 1 for i in range(64) if flag_mask & (1 << i)]
        else:
            flag_ids = None

        parser.seek(fields['chunks'])
        chunk_count, = parser.unpack('<L')  # _ == 0
        chunk_ids = list(parser.unpack(f'<{chunk_count}Q'))

        return fields['name'], fields['link'], flag_ids, fields['directory_id'], fields['file_size'], chunk_ids

    @classmethod
    def _parse_directory(cls, parser):
        """Parse a directory entry
        (name, directory_id, parent_id)
        """
        fields = cls._parse_field_table(parser, (
            None,
            None,
            ('directory_id', '<Q'),
            ('parent_id', '<Q'),
            ('name', 'str'),
        ))
        return fields['name'], fields['directory_id'], fields['parent_id']

    @staticmethod
    def _parse_field_table(parser, fields):
        entry_pos = parser.tell()
        fields_pos = entry_pos - parser.unpack('<l')[0]
        nfields = len(fields)
        output = {}
        parser.seek(fields_pos)
        for i, field, offset in zip(range(nfields), fields, parser.unpack(f'<{nfields}H')):
            if field is None:
                continue
            name, fmt = field
            if offset == 0 or fmt is None:
                value = None
            else:
                pos = entry_pos + offset
                if fmt == 'offset':
                    value = pos
                elif fmt == 'str':
                    parser.seek(pos)
                    value = parser.unpack('<l')[0]
                    parser.seek(pos + value)
                    value = parser.unpack_string()
                else:
                    parser.seek(pos)
                    value = parser.unpack(fmt)[0]
            output[name] = value
        return output


class ManifestDeploy:
    SERVER = 'https://lol.dyn.riotcdn.net/channels/public/bundles/'

    def __init__(self, path):
        self.path = path
        self.error_chunks = []

    def _get_path(self, path):
        return os.path.join(self.path, path)

    def load_chunk(self, chunk: PatcherChunk):
        """Load chunk data from a bundle"""
        path = f"Bundles/{chunk.bundle.bundle_id:016X}.bundle"

        try:
            with open(self._get_path(path), "rb") as f:
                f.seek(chunk.offset)
                # assume chunk is compressed
                return zstd.decompress(f.read(chunk.size))
        except Exception as e:
            logger.error(f'{e}: {self._get_path(path)}')
            self.error_chunks.append(chunk.chunk_id)
            if os.path.exists(self._get_path(path)):
                os.remove(self._get_path(path))

    def extract_file(self, file: PatcherFile, overwrite=False):
        """Extract a file from its chunks, which must be available"""
        if file.name[:4].lower() == 'data':
            output = os.path.join(self.path, 'out', 'Game', file.name)
        else:
            output = os.path.join(self.path, 'out', 'LeagueClient', file.name)

        if not overwrite and os.path.isfile(output) and os.path.getsize(output) == file.size:
            # logger.debug(f"skip {file.name}: already built to {output}")
            return
        output_dir = os.path.dirname(output)
        os.makedirs(output_dir, exist_ok=True)

        if overwrite or not os.path.isfile(output):
            try:
                with write_file_or_remove(output) as f:
                    for chunk in file.chunks:
                        if chunk in self.error_chunks:
                            logger.error(f'遇到错误跳过: {file.name}')
                            break
                        f.write(self.load_chunk(chunk))
            except Exception as e:
                logger.error(f"failed to extract {e}")

    def get_bundles_url(self, _id):
        return f'{self.SERVER}{_id:016X}.bundle'


def get_manifest_diff(o: Manifest, n: Manifest, region='zh_cn', detail=False):
    """
    获取 不同版本区域资源差异
    :param o: 旧版本
    :param n: 新版本
    :param region: 区域
    :param detail: 是否显示详细, 区分 新增、变化
    :return: 文件名列表，如果detail为True 返回 dict(new=[], size=[], hash=[])
    """
    a_files = filter(lambda _f: any(f.lower() == region.lower() for f in _f.flags), o.files.values())
    b_files = filter(lambda _f: any(f.lower() == region.lower() for f in _f.flags), n.files.values())
    a_files = {_f.name: _f for _f in a_files}
    result = []
    result_info = dict(new=[], diff=[])
    for file in b_files:
        if file.name not in a_files:
            logger.debug(f'新增文件: {file.name}')
            result.append(file.name)
            result_info['new'].append(file.name)
        else:
            if file.size != a_files[file.name].size:
                logger.debug(f'文件大小不同: {file.name}')
                result.append(file.name)
                result_info['diff'].append(file.name)
            else:
                if file.hexdigest() != a_files[file.name].hexdigest():
                    logger.debug(f'文件内容不同: {file.name}')
                    result.append(file.name)
                    result_info['diff'].append(file.name)

    return result_info if detail else result

