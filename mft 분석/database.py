import ast
import json
import re

import psycopg

from psycopg.rows import dict_row

from psycopg.types.json import Jsonb

from qdrant_client import (
    QdrantClient,
    models,
)

from config import *


DB = None

QDRANT = None


def clean(value):

    if value is None:

        return ""

    return str(
        value
    ).strip()


def to_db_int(
    value,
):

    if value is None:

        return None

    if isinstance(
        value,
        bool,
    ):

        return (
            1
            if value
            else 0
        )

    if isinstance(
        value,
        int,
    ):

        return value

    if isinstance(
        value,
        float,
    ):

        return int(
            value
        )

    text = (
        str(
            value
        )
        .strip()
        .lower()
    )

    if not text:

        return None

    if text in {
        "true",
        "yes",
        "y",
    }:

        return 1

    if text in {
        "false",
        "no",
        "n",
    }:

        return 0

    try:

        return int(
            float(
                text
            )
        )

    except Exception:

        return None


def normalize_tags(
    raw_value,
):

    if raw_value is None:

        return []

    if isinstance(
        raw_value,
        (
            list,
            tuple,
            set,
        ),
    ):

        values = list(
            raw_value
        )

    else:

        text = clean(
            raw_value
        )

        if not text:

            return []

        values = None

        if (
            text.startswith("[")
            and
            text.endswith("]")
        ):

            try:

                parsed = json.loads(
                    text
                )

                if isinstance(
                    parsed,
                    list,
                ):

                    values = parsed

            except Exception:

                pass

            if values is None:

                try:

                    parsed = (
                        ast.literal_eval(
                            text
                        )
                    )

                    if isinstance(
                        parsed,
                        (
                            list,
                            tuple,
                            set,
                        ),
                    ):

                        values = list(
                            parsed
                        )

                except Exception:

                    pass

        if values is None:

            values = re.split(
                r"[,;|]",
                text,
            )

    result = []

    seen = set()

    for value in values:

        tag = clean(
            value
        )

        if not tag:

            continue

        key = (
            tag.lower()
        )

        if key in seen:

            continue

        seen.add(
            key
        )

        result.append(
            tag
        )

    return result


def connect_all():

    global DB

    global QDRANT

    DB = psycopg.connect(

        host=
            POSTGRES_HOST,

        port=
            POSTGRES_PORT,

        dbname=
            POSTGRES_DB,

        user=
            POSTGRES_USER,

        password=
            POSTGRES_PASSWORD,

        row_factory=
            dict_row,
    )

    QDRANT = (
        QdrantClient(
            url=
                QDRANT_URL
        )
    )

    return (
        DB,
        QDRANT,
    )


def close_all():

    global DB

    if DB is not None:

        try:

            DB.close()

        except Exception:

            pass


def get_db():

    if DB is None:

        raise RuntimeError(
            "PostgreSQL 연결이 "
            "초기화되지 않았습니다."
        )

    return DB


def get_qdrant():

    if QDRANT is None:

        raise RuntimeError(
            "Qdrant 연결이 "
            "초기화되지 않았습니다."
        )

    return QDRANT


def db_table_exists():

    db = get_db()

    with db.cursor() as cur:

        cur.execute(
            """
            SELECT EXISTS
            (
                SELECT
                    1
                FROM
                    information_schema.tables
                WHERE
                    table_schema = 'public'
                    AND
                    table_name = %s
            )
                AS exists
            """,
            (
                TABLE_NAME,
            ),
        )

        row = (
            cur.fetchone()
        )

    return bool(
        row[
            "exists"
        ]
    )


def get_db_count():

    db = get_db()

    with db.cursor() as cur:

        cur.execute(
            f"""
            SELECT
                COUNT(*) AS count
            FROM
                {TABLE_NAME}
            """
        )

        row = (
            cur.fetchone()
        )

    return int(
        row[
            "count"
        ]
    )


def recreate_schema():

    db = get_db()

    with db.cursor() as cur:

        cur.execute(
            f"""
            DROP TABLE IF EXISTS
                {TABLE_NAME}
            CASCADE
            """
        )

        cur.execute(
            f"""
            CREATE TABLE
                {TABLE_NAME}
            (
                record_id
                    BIGINT
                    PRIMARY KEY,

                source_image
                    TEXT,

                entry_number
                    BIGINT,

                sequence_number
                    BIGINT,

                deleted
                    INTEGER,

                parent_path
                    TEXT,

                file_name
                    TEXT,

                file_size
                    BIGINT,

                is_directory
                    INTEGER,

                has_ads
                    INTEGER,

                is_ads
                    INTEGER,

                si_lt_fn
                    INTEGER,

                usec_zeros
                    INTEGER,

                copied
                    INTEGER,

                si_flags
                    TEXT,

                created_si
                    TIMESTAMPTZ,

                created_fn
                    TIMESTAMPTZ,

                modified_si
                    TIMESTAMPTZ,

                modified_fn
                    TIMESTAMPTZ,

                record_change_si
                    TIMESTAMPTZ,

                access_si
                    TIMESTAMPTZ,

                name_type_odd
                    INTEGER,

                has_efs
                    INTEGER,

                resident_data_is_binary
                    INTEGER,

                exec_in_odd_place
                    INTEGER,

                persistence_place
                    INTEGER,

                tamper_target
                    INTEGER,

                staging_archive
                    INTEGER,

                in_incident_window
                    INTEGER,

                os_servicing_path
                    INTEGER,

                tags
                    TEXT[],

                payload
                    JSONB
                    NOT NULL,

                search_text
                    TEXT,

                search_vector
                    TSVECTOR
                    GENERATED ALWAYS AS
                    (
                        to_tsvector
                        (
                            'simple',
                            COALESCE(
                                search_text,
                                ''
                            )
                        )
                    )
                    STORED
            )
            """
        )

    db.commit()


def get_insert_columns():

    return (
        [
            "record_id",
            "source_image",
        ]
        +
        DB_EXTRACT_FIELDS
        +
        [
            "tags",
            "payload",
            "search_text",
        ]
    )


def make_search_text(
    payload,
):

    parts = []

    for field in (
        "file_name",
        "parent_path",
        "si_flags",
        "hard_keep_reason",
        "reparse_target",
        "host",
    ):

        value = clean(
            payload.get(
                field
            )
        )

        if value:

            parts.append(
                value
            )

    parts.extend(
        normalize_tags(
            payload.get(
                "tags"
            )
        )
    )

    return " ".join(
        parts
    )


def normalize_payload_for_db(
    payload,
    pc_name,
):

    payload[
        "source_image"
    ] = (
        clean(
            payload.get(
                "source_image"
            )
        )
        or
        clean(
            payload.get(
                "host"
            )
        )
        or
        pc_name
    )

    payload[
        "tags"
    ] = (
        normalize_tags(
            payload.get(
                "tags"
            )
        )
    )

    if (
        "deleted"
        not in
        payload
        and
        "in_use"
        in
        payload
    ):

        in_use = (
            to_db_int(
                payload.get(
                    "in_use"
                )
            )
        )

        if in_use is not None:

            payload[
                "deleted"
            ] = (
                0
                if in_use == 1
                else 1
            )

    for field in (
        DB_INTEGER_FIELDS
    ):

        if (
            field
            not in
            payload
        ):

            continue

        value = (
            to_db_int(
                payload.get(
                    field
                )
            )
        )

        if value is None:

            payload.pop(
                field,
                None,
            )

        else:

            payload[
                field
            ] = value

    return payload


def build_db_row(
    record_id,
    payload,
):

    values = []

    for column in (
        get_insert_columns()
    ):

        if column == "record_id":

            value = (
                record_id
            )

        elif column == "source_image":

            value = (
                payload.get(
                    "source_image"
                )
            )

        elif column == "tags":

            value = (
                normalize_tags(
                    payload.get(
                        "tags"
                    )
                )
            )

        elif column == "payload":

            value = (
                Jsonb(
                    payload
                )
            )

        elif column == "search_text":

            value = (
                make_search_text(
                    payload
                )
            )

        else:

            value = (
                payload.get(
                    column
                )
            )

            if (
                column
                in
                DB_INTEGER_FIELDS
            ):

                value = (
                    to_db_int(
                        value
                    )
                )

        values.append(
            value
        )

    return tuple(
        values
    )


def insert_rows(
    rows,
):

    if not rows:

        return

    db = get_db()

    columns = (
        get_insert_columns()
    )

    placeholders = (
        ", ".join(
            [
                "%s"
            ]
            *
            len(
                columns
            )
        )
    )

    sql = (
        f"INSERT INTO "
        f"{TABLE_NAME} "
        f"({', '.join(columns)}) "
        f"VALUES "
        f"({placeholders})"
    )

    with db.cursor() as cur:

        cur.executemany(
            sql,
            rows,
        )

    db.commit()


def ingest_jsonl(
    pc_name,
    jsonl_path,
):

    record_id = 1

    inserted = 0

    pending = []

    with open(
        jsonl_path,
        "r",
        encoding="utf-8",
    ) as file:

        for (
            line_number,
            line,
        ) in enumerate(
            file,
            start=1,
        ):

            line = (
                line.strip()
            )

            if not line:

                continue

            try:

                payload = (
                    json.loads(
                        line
                    )
                )

            except Exception as exc:

                raise ValueError(
                    "JSONL 파싱 실패 | "
                    f"line={line_number} | "
                    f"{exc}"
                )

            payload = (
                normalize_payload_for_db(
                    payload,
                    pc_name,
                )
            )

            pending.append(
                build_db_row(
                    record_id,
                    payload,
                )
            )

            record_id += 1

            if (
                len(
                    pending
                )
                >=
                DB_INSERT_BATCH_SIZE
            ):

                insert_rows(
                    pending
                )

                inserted += len(
                    pending
                )

                print(
                    "\rPostgreSQL 적재: "
                    f"{inserted:,}",
                    end="",
                    flush=True,
                )

                pending.clear()

    if pending:

        insert_rows(
            pending
        )

        inserted += len(
            pending
        )

    print()

    return inserted


def create_indexes():

    db = get_db()

    with db.cursor() as cur:

        cur.execute(
            f"""
            CREATE INDEX
                idx_mft_search_vector
            ON
                {TABLE_NAME}
            USING
                GIN(search_vector)
            """
        )

        cur.execute(
            f"""
            CREATE INDEX
                idx_mft_tags
            ON
                {TABLE_NAME}
            USING
                GIN(tags)
            """
        )

        cur.execute(
            f"""
            CREATE INDEX
                idx_mft_filename_lower
            ON
                {TABLE_NAME}
                (LOWER(file_name))
            """
        )

        cur.execute(
            f"""
            CREATE INDEX
                idx_mft_parent_path_lower
            ON
                {TABLE_NAME}
                (LOWER(parent_path))
            """
        )

        for field in sorted(
            QUERY_FLAG_FIELDS
        ):

            cur.execute(
                f"""
                CREATE INDEX
                    idx_mft_{field}
                ON
                    {TABLE_NAME}
                    ({field})
                """
            )

        cur.execute(
            f"""
            CREATE INDEX
                idx_mft_created_si
            ON
                {TABLE_NAME}
                (created_si)
            """
        )

        cur.execute(
            f"""
            CREATE INDEX
                idx_mft_record_change_si
            ON
                {TABLE_NAME}
                (record_change_si)
            """
        )

        cur.execute(
            f"""
            ANALYZE
                {TABLE_NAME}
            """
        )

    db.commit()


def ensure_dense_collection(
    reset=False,
):

    qdrant = (
        get_qdrant()
    )

    exists = (
        qdrant.collection_exists(
            COLLECTION_NAME
        )
    )

    if (
        reset
        and
        exists
    ):

        qdrant.delete_collection(
            collection_name=
                COLLECTION_NAME
        )

        exists = False

    if not exists:

        qdrant.create_collection(

            collection_name=
                COLLECTION_NAME,

            vectors_config={

                "dense":
                    models.VectorParams(

                        size=
                            EMBED_DIM,

                        distance=
                            models.Distance.COSINE,
                    )
            },
        )


def get_dense_cache_count():

    qdrant = (
        get_qdrant()
    )

    try:

        info = (
            qdrant.get_collection(
                COLLECTION_NAME
            )
        )

        return int(
            info.points_count
            or 0
        )

    except Exception:

        return 0
