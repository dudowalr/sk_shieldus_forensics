# BUILD_ID: 2026-08-17-TIMELINE-BURST-CONTEXT-V1
import re

from collections import defaultdict

from datetime import datetime

from pathlib import Path

from config import *

import database


def clean(
    value,
):

    if value is None:

        return ""

    return str(
        value
    ).strip()


def normalize_path(
    value,
):

    return (
        clean(
            value
        )
        .lower()
        .replace(
            "/",
            "\\",
        )
    )


def get_extension(
    file_name,
):

    return (
        Path(
            clean(
                file_name
            )
        )
        .suffix
        .lower()
    )


def parse_timestamp(
    value,
):

    text = clean(
        value
    )

    if not text:

        return None

    if text.endswith(
        "Z"
    ):

        text = (
            text[:-1]
            +
            "+00:00"
        )

    match = re.match(
        r"^(.*\.\d{6})\d+(.*)$",
        text,
    )

    if match:

        text = (
            match.group(1)
            +
            match.group(2)
        )

    try:

        return (
            datetime
            .fromisoformat(
                text
            )
        )

    except Exception:

        return None


def get_activity_timestamp(
    payload,
):

    # MFT 기반 파일 활동 Context용.
    # 실행시각을 의미하지 않는다.
    for field in (
        "created_si",
        "record_change_si",
        "created_fn",
        "modified_si",
        "modified_fn",
    ):

        raw = (
            payload.get(
                field
            )
        )

        parsed = (
            parse_timestamp(
                raw
            )
        )

        if parsed is not None:

            return (
                parsed,
                field,
                raw,
            )

    return (
        None,
        None,
        None,
    )


def record_features(
    payload,
):

    result = []

    extension = (
        get_extension(
            payload.get(
                "file_name"
            )
        )
    )

    if extension:

        result.append(
            f"extension:{extension}"
        )

    for field in (
        "deleted",
        "exec_in_odd_place",
        "persistence_place",
        "staging_archive",
        "has_ads",
        "is_ads",
        "si_lt_fn",
    ):

        if (
            payload.get(
                field
            )
            ==
            1
        ):

            result.append(
                field
            )

    return result


def fetch_path_neighbors(
    search_points,
):

    paths = []

    seen = set()

    for point in (
        search_points[
            :BEHAVIOR_SEED_LIMIT
        ]
    ):

        path = clean(
            point.payload.get(
                "parent_path"
            )
        )

        key = (
            path.lower()
        )

        if (
            path
            and
            key
            not in
            seen
        ):

            seen.add(
                key
            )

            paths.append(
                path
            )

    rows = []

    db = (
        database.get_db()
    )

    for path in paths:

        with db.cursor() as cur:

            cur.execute(
                f"""
                SELECT
                    record_id,
                    payload
                FROM
                    {TABLE_NAME}
                WHERE
                    LOWER(parent_path)
                    =
                    LOWER(%s)
                ORDER BY
                    record_id ASC
                LIMIT %s
                """,
                (
                    path,
                    BEHAVIOR_NEIGHBOR_PER_PATH,
                ),
            )

            rows.extend(
                cur.fetchall()
            )

    unique = {

        int(
            row[
                "record_id"
            ]
        ):
            row

        for row in rows
    }

    return list(
        unique.values()
    )


def looks_like_servicing(
    path,
    files,
):

    path = (
        normalize_path(
            path
        )
    )

    names = {

        clean(
            file
        ).lower()

        for file in files

        if clean(
            file
        )
    }

    if (
        "\\windows\\winsxs\\temp\\"
        in
        path
    ):

        return True

    if (
        "\\windows\\servicing\\"
        in
        path
    ):

        return True

    if (
        "\\temp\\"
        not in
        path
    ):

        return False

    # DismHost.exe.locked 같은 형태도 포함
    has_dism_host = any(

        name == "dismhost.exe"
        or
        name.startswith(
            "dismhost.exe."
        )

        for name in names
    )

    provider_count = sum(

        1

        for name in names

        if (
            name.endswith(
                "provider.dll"
            )
            or
            name
            in
            {
                "dismprov.dll",
                "dismcore.dll",
                "dismcoreps.dll",
                "wimprovider.dll",
                "msiprovider.dll",
                "genericprovider.dll",
                "appxprovider.dll",
                "cbsprovider.dll",
                "assocprovider.dll",
                "compatprovider.dll",
                "dmiprovider.dll",
                "ffuprovider.dll",
                "folderprovider.dll",
                "imagingprovider.dll",
                "intlprovider.dll",
                "logprovider.dll",
                "offlinesetupprovider.dll",
                "osprovider.dll",
            }
        )
    )

    api_ms_count = sum(

        1

        for name in names

        if name.startswith(
            "api-ms-win-"
        )
    )

    # 단일 파일명 하나로 판단하지 않고
    # DISM host + provider 조합 또는
    # provider 다수 조합을 Context 힌트로 사용.
    return (
        (
            has_dism_host
            and
            provider_count
            >=
            2
        )
        or
        provider_count
        >=
        6
        or
        (
            provider_count
            >=
            2
            and
            api_ms_count
            >=
            4
        )
    )


def looks_like_defender_definition_update(
    path,
):
    """
    Windows Defender Definition Updates 경로 여부.

    정상이라고 단정하지 않고
    possible_defender_definition_update Context만 부여한다.
    """

    path = (
        normalize_path(
            path
        )
    )

    return (
        "\\programdata\\microsoft\\windows defender\\definition updates\\"
        in
        path
    )


def calculate_activity_burst(
    records,
):
    """
    같은 경로의 MFT 활동에서
    BEHAVIOR_TIME_WINDOW_SECONDS 안에 가장 많은 레코드가 포함되는
    시간 구간을 찾는다.

    목적:
    - "처음 집중되기 시작한 시점"
    - "활동이 몰린 구간"
    같은 Timeline 질문에 사용할 사실 기반 Context 생성.

    주의:
    실행 시각이 아니라 MFT timestamp 기반 파일 활동 구간이다.
    """

    timed = [
        record
        for record in records
        if record.get(
            "timestamp"
        )
        is not None
    ]

    if not timed:

        return {
            "burst_start": None,
            "burst_end": None,
            "burst_count": 0,
            "burst_span_seconds": None,
            "burst_density": 0.0,
        }

    timed.sort(
        key=
            lambda record:
                record[
                    "timestamp"
                ]
    )

    left = 0

    best_left = 0
    best_right = 0
    best_count = 1
    best_span = 0.0

    for right in range(
        len(
            timed
        )
    ):

        while (
            timed[
                right
            ][
                "timestamp"
            ]
            -
            timed[
                left
            ][
                "timestamp"
            ]
        ).total_seconds() > BEHAVIOR_TIME_WINDOW_SECONDS:

            left += 1

        count = (
            right
            -
            left
            +
            1
        )

        span = (
            timed[
                right
            ][
                "timestamp"
            ]
            -
            timed[
                left
            ][
                "timestamp"
            ]
        ).total_seconds()

        # 같은 count면 더 짧은 burst,
        # 그것도 같으면 더 이른 burst를 선택.
        if (
            count > best_count
            or
            (
                count == best_count
                and
                span < best_span
            )
            or
            (
                count == best_count
                and
                span == best_span
                and
                timed[
                    left
                ][
                    "timestamp"
                ]
                <
                timed[
                    best_left
                ][
                    "timestamp"
                ]
            )
        ):

            best_left = left
            best_right = right
            best_count = count
            best_span = span

    start = (
        timed[
            best_left
        ][
            "timestamp"
        ]
    )

    end = (
        timed[
            best_right
        ][
            "timestamp"
        ]
    )

    # 동일 timestamp 다수도 표현 가능하도록 최소 1초 분모.
    density = (
        best_count
        /
        max(
            best_span,
            1.0,
        )
    )

    return {
        "burst_start":
            start.isoformat(),

        "burst_end":
            end.isoformat(),

        "burst_count":
            int(
                best_count
            ),

        "burst_span_seconds":
            float(
                best_span
            ),

        "burst_density":
            float(
                density
            ),
    }


def looks_like_mei_bundle(
    path,
    files,
):

    path = (
        normalize_path(
            path
        )
    )

    if (
        "\\temp\\_mei"
        not in
        path
    ):

        return False

    names = {

        clean(
            file
        ).lower()

        for file in files

        if clean(
            file
        )
    }

    indicators = {
        "python314.dll",
        "python313.dll",
        "python312.dll",
        "python311.dll",
        "vcruntime140.dll",
        "vcruntime140_1.dll",
        "libcrypto-3.dll",
        "libssl-3.dll",
        "libffi-8.dll",
    }

    return (
        len(
            indicators
            &
            names
        )
        >=
        2
    )


def analyze_rows(
    rows,
):

    groups = (
        defaultdict(
            list
        )
    )

    for row in rows:

        payload = (
            row.get(
                "payload"
            )
            or
            {}
        )

        path = (
            normalize_path(
                payload.get(
                    "parent_path"
                )
            )
        )

        if not path:

            continue

        (
            timestamp,
            timestamp_field,
            timestamp_raw,
        ) = (
            get_activity_timestamp(
                payload
            )
        )

        groups[
            path
        ].append(
            {
                "record_id":
                    int(
                        row[
                            "record_id"
                        ]
                    ),

                "file_name":
                    clean(
                        payload.get(
                            "file_name"
                        )
                    ),

                "extension":
                    get_extension(
                        payload.get(
                            "file_name"
                        )
                    ),

                "timestamp":
                    timestamp,

                "timestamp_field":
                    timestamp_field,

                "timestamp_raw":
                    timestamp_raw,

                "payload":
                    payload,
            }
        )

    clusters = []

    record_context = {}

    for (
        path,
        records,
    ) in groups.items():

        if len(records) < 2:

            continue

        files = [

            record[
                "file_name"
            ]

            for record in records
        ]

        extensions = {

            record[
                "extension"
            ]

            for record in records

            if record[
                "extension"
            ]
        }

        exe_count = sum(

            1

            for record in records

            if (
                record[
                    "extension"
                ]
                ==
                ".exe"
            )
        )

        dll_count = sum(

            1

            for record in records

            if (
                record[
                    "extension"
                ]
                ==
                ".dll"
            )
        )

        sys_count = sum(

            1

            for record in records

            if (
                record[
                    "extension"
                ]
                ==
                ".sys"
            )
        )

        script_count = sum(

            1

            for record in records

            if (
                record[
                    "extension"
                ]
                in
                SCRIPT_EXTENSIONS
            )
        )

        archive_count = sum(

            1

            for record in records

            if (
                record[
                    "extension"
                ]
                in
                ARCHIVE_EXTENSIONS
            )
        )

        executable_count = sum(

            1

            for record in records

            if (
                record[
                    "extension"
                ]
                in
                EXECUTABLE_EXTENSIONS
            )
        )

        deleted_count = sum(

            1

            for record in records

            if (
                record[
                    "payload"
                ]
                .get(
                    "deleted"
                )
                ==
                1
            )
        )

        exec_odd_count = sum(

            1

            for record in records

            if (
                record[
                    "payload"
                ]
                .get(
                    "exec_in_odd_place"
                )
                ==
                1
            )
        )

        persistence_count = sum(

            1

            for record in records

            if (
                record[
                    "payload"
                ]
                .get(
                    "persistence_place"
                )
                ==
                1
            )
        )

        staging_count = sum(

            1

            for record in records

            if (
                record[
                    "payload"
                ]
                .get(
                    "staging_archive"
                )
                ==
                1
            )
        )

        timestamps = [

            record[
                "timestamp"
            ]

            for record in records

            if (
                record[
                    "timestamp"
                ]
                is not None
            )
        ]

        first_activity = None

        last_activity = None

        time_span_seconds = None

        burst = (
            calculate_activity_burst(
                records
            )
        )

        if timestamps:

            first = min(
                timestamps
            )

            last = max(
                timestamps
            )

            first_activity = (
                first.isoformat()
            )

            last_activity = (
                last.isoformat()
            )

            time_span_seconds = (
                last
                -
                first
            ).total_seconds()

        labels = []

        if len(records) >= 3:

            labels.append(
                "same_path_cluster"
            )

        if (
            time_span_seconds
            is not None
            and
            time_span_seconds
            <=
            BEHAVIOR_TIME_WINDOW_SECONDS
            and
            len(records)
            >=
            3
        ):

            labels.append(
                "same_path_time_cluster"
            )

        if (
            executable_count
            >=
            2
        ):

            labels.append(
                "multiple_executable_files"
            )

        if (
            exe_count
            >=
            1
            and
            sys_count
            >=
            1
        ):

            labels.append(
                "exe_plus_driver"
            )

        if (
            exe_count
            >=
            1
            and
            script_count
            >=
            1
        ):

            labels.append(
                "exe_plus_script"
            )

        if (
            archive_count
            >=
            1
            and
            executable_count
            >=
            1
        ):

            # 동시 존재(co-presence)만 의미한다.
            # Archive -> Executable 순서를 증명하지 않는다.
            labels.append(
                "archive_plus_executable"
            )

        if (
            executable_count
            >=
            2
            and
            deleted_count
            >=
            2
        ):

            labels.append(
                "deleted_executable_cluster"
            )

        if (
            executable_count
            >=
            2
            and
            exec_odd_count
            >=
            2
        ):

            labels.append(
                "odd_executable_cluster"
            )

        if (
            persistence_count
            >=
            2
        ):

            labels.append(
                "persistence_location_cluster"
            )

        if (
            staging_count
            >=
            1
            and
            executable_count
            >=
            1
        ):

            labels.append(
                "staging_plus_executable"
            )

        normal_context_hint = None

        if (
            looks_like_defender_definition_update(
                path
            )
        ):

            normal_context_hint = (
                "possible_defender_definition_update"
            )

        elif (
            looks_like_servicing(
                path,
                files,
            )
        ):

            normal_context_hint = (
                "possible_windows_servicing"
            )

        elif (
            looks_like_mei_bundle(
                path,
                files,
            )
        ):

            normal_context_hint = (
                "possible_packaged_python_runtime"
            )

        # 검색/표시 보조용.
        # 악성도 점수가 아니다.
        behavior_priority = 0.0

        weights = [
            (
                "same_path_cluster",
                0.4,
            ),
            (
                "same_path_time_cluster",
                0.8,
            ),
            (
                "multiple_executable_files",
                0.8,
            ),
            (
                "exe_plus_driver",
                2.0,
            ),
            (
                "exe_plus_script",
                1.6,
            ),
            (
                "archive_plus_executable",
                1.4,
            ),
            (
                "deleted_executable_cluster",
                0.8,
            ),
            (
                "odd_executable_cluster",
                1.5,
            ),
            (
                "persistence_location_cluster",
                1.3,
            ),
            (
                "staging_plus_executable",
                1.3,
            ),
        ]

        for (
            label,
            weight,
        ) in weights:

            if label in labels:

                behavior_priority += (
                    weight
                )

        if (
            normal_context_hint
            is not None
        ):

            behavior_priority *= (
                0.15
            )

        cluster = {
            "path":
                path,

            "record_count":
                len(
                    records
                ),

            "files":
                files[
                    :100
                ],

            "extensions":
                sorted(
                    extensions
                ),

            "exe_count":
                exe_count,

            "dll_count":
                dll_count,

            "sys_count":
                sys_count,

            "script_count":
                script_count,

            "archive_count":
                archive_count,

            "executable_count":
                executable_count,

            "deleted_count":
                deleted_count,

            "exec_odd_count":
                exec_odd_count,

            "persistence_count":
                persistence_count,

            "staging_count":
                staging_count,

            "first_activity":
                first_activity,

            "last_activity":
                last_activity,

            "time_span_seconds":
                time_span_seconds,

            "burst_start":
                burst[
                    "burst_start"
                ],

            "burst_end":
                burst[
                    "burst_end"
                ],

            "burst_count":
                burst[
                    "burst_count"
                ],

            "burst_span_seconds":
                burst[
                    "burst_span_seconds"
                ],

            "burst_density":
                burst[
                    "burst_density"
                ],

            "cluster_features":
                labels,

            "normal_context_hint":
                normal_context_hint,

            "behavior_priority":
                behavior_priority,
        }

        clusters.append(
            cluster
        )

        for record in records:

            record_context[
                record[
                    "record_id"
                ]
            ] = {
                "record_features":
                    record_features(
                        record[
                            "payload"
                        ]
                    ),

                "cluster_features":
                    list(
                        labels
                    ),

                "cluster_path":
                    path,

                "cluster_behavior_priority":
                    behavior_priority,

                "normal_context_hint":
                    normal_context_hint,

                "cluster_first_activity":
                    first_activity,

                "cluster_last_activity":
                    last_activity,

                "cluster_time_span_seconds":
                    time_span_seconds,

                "cluster_burst_start":
                    burst[
                        "burst_start"
                    ],

                "cluster_burst_end":
                    burst[
                        "burst_end"
                    ],

                "cluster_burst_count":
                    burst[
                        "burst_count"
                    ],

                "cluster_burst_span_seconds":
                    burst[
                        "burst_span_seconds"
                    ],

                "cluster_burst_density":
                    burst[
                        "burst_density"
                    ],
            }

    clusters.sort(

        key=
            lambda item:
                (
                    item[
                        "behavior_priority"
                    ],
                    item[
                        "record_count"
                    ],
                ),

        reverse=True,
    )

    return (
        clusters,
        record_context,
    )


def analyze_search_context(
    search_points,
):

    rows = (
        fetch_path_neighbors(
            search_points
        )
    )

    (
        clusters,
        record_context,
    ) = (
        analyze_rows(
            rows
        )
    )

    return (
        clusters,
        record_context,
        rows,
    )
