import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

CSV_ROOT = BASE_DIR / "csv"

MFT_SLIM_SCRIPT = (
    BASE_DIR
    / "mft_slim"
    / "mft_slim.py"
)

PAYLOAD_SCRIPT = (
    BASE_DIR
    / "mft_to_payload.py"
)


# ============================================================
# PostgreSQL
# ============================================================

POSTGRES_HOST = "127.0.0.1"
POSTGRES_PORT = 5433
POSTGRES_DB = "forensic"
POSTGRES_USER = "rookies"

POSTGRES_PASSWORD = os.getenv(
    "MFT_DB_PASSWORD",
    "1",
)

TABLE_NAME = "mft_records"


# ============================================================
# Qdrant
# ============================================================

QDRANT_URL = "http://127.0.0.1:6333"

COLLECTION_NAME = (
    "mft_dense_cache"
)


# ============================================================
# Ollama
# ============================================================

OLLAMA_URL = "http://127.0.0.1:11434"

EMBED_MODEL = (
    "qwen3-embedding:0.6b"
)

LLM_MODEL = (
    "qwen3.5:9b"
)

EMBED_DIM = 1024


# ============================================================
# Reranker
# ============================================================

RERANK_MODEL = (
    "jinaai/"
    "jina-reranker-v2-base-multilingual"
)


# ============================================================
# Batch / Retry
# ============================================================

DB_INSERT_BATCH_SIZE = 2000

EMBED_BATCH_SIZE = 128

HTTP_RETRIES = 3


# ============================================================
# Retrieval Limits
# ============================================================

SPARSE_LIMIT = 140

METADATA_BUCKET_LIMIT = 28

METADATA_REQUIRED_LIMIT = 100

MISMATCH_LIMIT = 80

INITIAL_CANDIDATE_LIMIT = 320


# ============================================================
# Behavior
# ============================================================

BEHAVIOR_SEED_LIMIT = 24

BEHAVIOR_NEIGHBOR_PER_PATH = 80

BEHAVIOR_EXPANSION_TOTAL = 220

BEHAVIOR_TIME_WINDOW_SECONDS = 600


# ============================================================
# Dense / Rerank
# ============================================================

DENSE_CANDIDATE_LIMIT = 180

DENSE_PER_PATH_CAP = 8

RERANK_LIMIT = 70

FINAL_RESULT_LIMIT = 20

DISPLAY_LIMIT = 12

RRF_K = 60


# ============================================================
# RRF Weights
#
# 모두 검색 관련성 Source 가중치이다.
# 악성도 가중치가 아니다.
# ============================================================

DENSE_RRF_WEIGHT = 1.00

SPARSE_RRF_WEIGHT = 1.00

METADATA_RRF_WEIGHT = 0.90

BEHAVIOR_RRF_WEIGHT = 0.55

MISMATCH_RRF_WEIGHT = 0.75


# ============================================================
# PostgreSQL Extract Fields
# ============================================================

DB_EXTRACT_FIELDS = [
    "entry_number",
    "sequence_number",
    "deleted",
    "parent_path",
    "file_name",
    "file_size",
    "is_directory",
    "has_ads",
    "is_ads",
    "si_lt_fn",
    "usec_zeros",
    "copied",
    "si_flags",
    "created_si",
    "created_fn",
    "modified_si",
    "modified_fn",
    "record_change_si",
    "access_si",
    "name_type_odd",
    "has_efs",
    "resident_data_is_binary",
    "exec_in_odd_place",
    "persistence_place",
    "tamper_target",
    "staging_archive",
    "in_incident_window",
    "os_servicing_path",
]


DB_INTEGER_FIELDS = {
    "entry_number",
    "sequence_number",
    "deleted",
    "file_size",
    "is_directory",
    "has_ads",
    "is_ads",
    "si_lt_fn",
    "usec_zeros",
    "copied",
    "name_type_odd",
    "has_efs",
    "resident_data_is_binary",
    "exec_in_odd_place",
    "persistence_place",
    "tamper_target",
    "staging_archive",
    "in_incident_window",
    "os_servicing_path",
}


QUERY_FLAG_FIELDS = {
    "deleted",
    "has_ads",
    "is_ads",
    "si_lt_fn",
    "usec_zeros",
    "copied",
    "name_type_odd",
    "has_efs",
    "resident_data_is_binary",
    "exec_in_odd_place",
    "persistence_place",
    "tamper_target",
    "staging_archive",
    "in_incident_window",
    "os_servicing_path",
}


# ============================================================
# Metadata Candidate Weights
#
# 후보 검색용 신호.
# 악성도 점수가 아니다.
# ============================================================

FLAG_WEIGHTS = {
    "persistence_place": 3.0,
    "staging_archive": 2.6,
    "exec_in_odd_place": 2.4,
    "in_incident_window": 1.9,
    "has_ads": 1.6,
    "is_ads": 1.6,
    "deleted": 0.8,
    "name_type_odd": 0.7,
    "si_lt_fn": 0.5,
    "usec_zeros": 0.2,
    "copied": 0.2,
    "tamper_target": 0.1,
    "os_servicing_path": 0.0,
}


TAG_WEIGHTS = {
    "mtime_lt_ctime": 0.2,
    "ctime_eq_mtime": 0.05,
    "zero_byte": 0.1,
    "hex_stem_16plus": 0.6,
    "extgroup:pe_binary": 0.9,
    "extgroup:shell_script": 1.0,
    "extgroup:web_script": 1.0,
    "extgroup:archive": 0.8,
}


# ============================================================
# Extensions
# ============================================================

EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".sys",
    ".scr",
    ".com",
    ".ocx",
    ".cpl",
}


SCRIPT_EXTENSIONS = {
    ".ps1",
    ".psm1",
    ".bat",
    ".cmd",
    ".vbs",
    ".vbe",
    ".wsf",
    ".js",
    ".jse",
}


ARCHIVE_EXTENSIONS = {
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
    ".cab",
}


# ============================================================
# NTFS 내부 메타파일 레코드
#
# 중요:
# 현재 데이터셋은 "$MFT CSV"다.
#
# $UsnJrnl이라는 MFT 엔트리와
# $UsnJrnl:$J 내부 이벤트를 파싱한 데이터는 다른 것이다.
#
# 따라서 아래 NTFS 내부 메타파일 "레코드 자체"는
# 일반 MFT Retrieval에서 제외한다.
#
# deleted / SI<FN / ADS / Timestamp / ExecOdd 등의
# 일반 파일 포렌식 메타데이터 필드는 그대로 사용한다.
# ============================================================

NTFS_METADATA_NAMES = {
    "$mft",
    "$mftmirr",
    "$logfile",
    "$volume",
    "$attrdef",
    "$bitmap",
    "$boot",
    "$badclus",
    "$secure",
    "$upcase",
    "$usnjrnl",
    "$usnjrnl:$j",
    "$usnjrnl:$max",
    "$repair",
    "$repair:$verify",
    "$repair:$corrupt",
    "$repair:$config",
    "$tops",
    "$tops:$t",
}


NTFS_METADATA_PREFIXES = (
    ".\\$extend",
)
