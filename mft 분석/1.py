# BUILD_ID: 2026-08-17-REGRESSION-BURST-OUTPUT-V1
import time

import requests

import database

import pipeline

import query_engine

import ai_engine

from config import *


# ============================================================
# 회귀 테스트 질문
#
# 목적:
# 질문 하나를 고친 뒤 다른 질문이 깨지는지 확인한다.
#
# 회귀 테스트에서는 LLM을 호출하지 않는다.
# Retrieval / Rank / Behavior 결과만 빠르게 비교한다.
# ============================================================

REGRESSION_QUESTIONS = [

    # 1. 경로 + Behavior
    (
        "Temp 경로에서 의심스러운 "
        "파일 활동이 있었는지 분석해줘"
    ),

    # 2. System-like + Odd Path
    (
        "정상 시스템 파일처럼 보이지만 "
        "비정상 경로에 있는 파일을 찾아줘"
    ),

    # 3. 삭제 + 실행계열
    (
        "삭제된 실행파일을 찾아줘"
    ),

    # 4. Persistence
    (
        "지속성 관련 위치에 존재하는 "
        "파일을 찾아줘"
    ),

    # 5. Timeline + Semantic
    (
        "랜섬웨어 관련 의심 파일 활동이 "
        "처음 집중되기 시작한 시점을 추정해줘"
    ),

    # 6. ADS
    (
        "ADS가 존재하거나 ADS 자체인 "
        "파일을 찾아줘"
    ),

    # 7. Behavior 조합
    (
        "같은 경로에 실행파일과 스크립트가 "
        "함께 존재하는 파일 활동을 찾아줘"
    ),

    # 8. 일반 anomaly
    (
        "비정상 경로에서 발견된 "
        "의심스러운 실행파일을 찾아줘"
    ),
]


def check_services():

    if not MFT_SLIM_SCRIPT.exists():

        raise FileNotFoundError(
            "mft_slim.py 없음: "
            f"{MFT_SLIM_SCRIPT}"
        )

    if not PAYLOAD_SCRIPT.exists():

        raise FileNotFoundError(
            "mft_to_payload.py 없음: "
            f"{PAYLOAD_SCRIPT}"
        )

    db = (
        database.get_db()
    )

    with db.cursor() as cur:

        cur.execute(
            "SELECT version()"
        )

        cur.fetchone()

    (
        database
        .get_qdrant()
        .get_collections()
    )

    response = (
        requests.get(

            f"{OLLAMA_URL}/api/tags",

            timeout=30,
        )
    )

    response.raise_for_status()

    names = [

        model.get(
            "name",
            "",
        )

        for model in (
            response
            .json()
            .get(
                "models",
                [],
            )
        )
    ]

    if not any(

        name.startswith(
            EMBED_MODEL
        )

        for name in names
    ):

        raise RuntimeError(
            "Embedding 모델 없음: "
            f"{EMBED_MODEL}"
        )

    if not any(

        name.startswith(
            LLM_MODEL
        )

        for name in names
    ):

        raise RuntimeError(
            "LLM 모델 없음: "
            f"{LLM_MODEL}"
        )

    print(
        "mft_slim.py: OK"
    )

    print(
        "mft_to_payload.py: OK"
    )

    print(
        "PostgreSQL: OK"
    )

    print(
        "Qdrant: OK"
    )

    print(
        "Embedding:",
        f"{EMBED_MODEL} OK",
    )

    print(
        "LLM:",
        f"{LLM_MODEL} OK",
    )


def print_results(
    points,
):

    print(
        "\n"
        "========================================\n"
        "검색 결과\n"
        "========================================"
    )

    for (
        rank,
        point,
    ) in enumerate(

        points[
            :DISPLAY_LIMIT
        ],

        start=1,
    ):

        payload = (
            point.payload
            or {}
        )

        print(
            f"\n[{rank}] "
            f"rerank="
            f"{point.rerank_score:.4f} | "
            f"fused="
            f"{point.fused_score:.4f} | "
            f"dense="
            f"{point.dense_score:.4f} | "
            f"sparse="
            f"{point.sparse_score:.4f} | "
            f"behavior="
            f"{point.behavior_score:.2f}"
        )

        print(
            "record_id:",
            point.id,
        )

        print(
            "PC:",
            payload.get(
                "source_image",
                "",
            ),
        )

        print(
            "Entry:",
            payload.get(
                "entry_number",
                "",
            ),
        )

        print(
            "File:",
            payload.get(
                "file_name",
                "",
            ),
        )

        print(
            "Path:",
            payload.get(
                "parent_path",
                "",
            ),
        )

        print(
            "Size:",
            payload.get(
                "file_size",
                "",
            ),
        )

        print(
            "Deleted:",
            payload.get(
                "deleted",
                "",
            ),
        )

        print(
            "ExecOdd:",
            payload.get(
                "exec_in_odd_place",
                "",
            ),
        )

        print(
            "Retrieval:",
            point.retrieval_reason,
        )

        print(
            "Record Features:",
            point.record_features,
        )

        print(
            "Cluster Features:",
            point.cluster_features,
        )

        print(
            "Normal Context:",
            point.normal_context_hint,
        )

        if point.reference_paths:

            print(
                "System Reference:",
                point.reference_paths,
            )

            print(
                "Same Size Reference:",
                point.reference_same_size,
            )

        print(
            "Tags:",
            payload.get(
                "tags",
                [],
            ),
        )


def print_clusters(
    clusters,
):

    print(
        "\n"
        "========================================\n"
        "상위 Behavior Cluster\n"
        "========================================"
    )

    for (
        index,
        cluster,
    ) in enumerate(

        clusters[
            :10
        ],

        start=1,
    ):

        print(
            f"\n[{index}] "
            f"priority="
            f"{cluster['behavior_priority']:.2f}"
        )

        print(
            "Path:",
            cluster[
                "path"
            ],
        )

        print(
            "Records:",
            cluster[
                "record_count"
            ],
        )

        print(
            "Files:",
            cluster[
                "files"
            ][
                :20
            ],
        )

        print(
            "Time Span:",
            cluster[
                "time_span_seconds"
            ],
        )

        print(
            "Burst Start:",
            cluster.get(
                "burst_start"
            ),
        )

        print(
            "Burst End:",
            cluster.get(
                "burst_end"
            ),
        )

        print(
            "Burst Count:",
            cluster.get(
                "burst_count"
            ),
        )

        print(
            "Burst Span:",
            cluster.get(
                "burst_span_seconds"
            ),
        )

        print(
            "Burst Density:",
            cluster.get(
                "burst_density"
            ),
        )

        print(
            "Cluster Features:",
            cluster[
                "cluster_features"
            ],
        )

        print(
            "Normal Context:",
            cluster[
                "normal_context_hint"
            ],
        )


def search_loop():

    print(
        "\n"
        "========================================\n"
        "MFT 검색 시작\n"
        "========================================"
    )

    print(
        "PostgreSQL:",
        f"{database.get_db_count():,}",
    )

    print(
        "Dense Cache:",
        f"{database.get_dense_cache_count():,}",
    )

    print(
        "종료: exit"
    )

    while True:

        query = (
            input(
                "\n질문: "
            )
            .strip()
        )

        if (
            query.lower()
            ==
            "exit"
        ):

            break

        if not query:

            continue

        started = (
            time.perf_counter()
        )

        (
            points,
            plan,
            clusters,
        ) = (
            query_engine.retrieve(
                query
            )
        )

        retrieval_end = (
            time.perf_counter()
        )

        if not points:

            print(
                "\n검색 결과 없음"
            )

            continue

        print_results(
            points
        )

        print_clusters(
            clusters
        )

        evidence = (
            ai_engine.build_evidence(

                query,

                plan,

                points,

                clusters,
            )
        )

        print(
            "\n"
            "========================================\n"
            f"{LLM_MODEL} 최종 분석\n"
            "========================================\n"
        )

        llm_started = (
            time.perf_counter()
        )

        answer = (
            ai_engine.ask_llm(

                query,

                plan,

                evidence,
            )
        )

        finished = (
            time.perf_counter()
        )

        print(
            answer
        )

        print(
            "\n"
            "----------------------------------------"
        )

        print(
            "Route:",
            plan[
                "mode"
            ],
        )

        print(
            "Intent:",
            plan[
                "intent"
            ],
        )

        print(
            "Topic:",
            plan[
                "topic"
            ],
        )

        print(
            "검색+Rank:",
            f"{retrieval_end-started:.2f}s",
        )

        print(
            "LLM:",
            f"{finished-llm_started:.2f}s",
        )

        print(
            "전체:",
            f"{finished-started:.2f}s",
        )

        print(
            "Dense Cache:",
            f"{database.get_dense_cache_count():,}",
        )


def regression_result_summary(
    points,
    clusters,
):

    ntfs_internal_count = 0

    directory_count = 0

    normal_context_count = 0

    reference_count = 0

    for point in points:

        payload = (
            point.payload
            or {}
        )

        file_name = str(
            payload.get(
                "file_name"
            )
            or ""
        ).lower()

        parent_path = str(
            payload.get(
                "parent_path"
            )
            or ""
        ).lower()

        base_name = (
            file_name
            .split(
                ":",
                1,
            )[0]
        )

        metadata_base_names = {

            str(
                name
            )
            .lower()
            .split(
                ":",
                1,
            )[0]

            for name in (
                NTFS_METADATA_NAMES
            )
        }

        if (
            base_name
            in
            metadata_base_names
            or
            any(

                parent_path.startswith(
                    str(
                        prefix
                    ).lower()
                )

                for prefix in (
                    NTFS_METADATA_PREFIXES
                )
            )
        ):

            ntfs_internal_count += 1

        if (
            payload.get(
                "is_directory"
            )
            ==
            1
        ):

            directory_count += 1

        if (
            point.normal_context_hint
        ):

            normal_context_count += 1

        if (
            point.reference_paths
        ):

            reference_count += 1

    return {
        "results":
            len(
                points
            ),

        "clusters":
            len(
                clusters
            ),

        "ntfs_internal_in_results":
            ntfs_internal_count,

        "directories_in_results":
            directory_count,

        "normal_context_results":
            normal_context_count,

        "system_reference_results":
            reference_count,
    }


def run_regression_tests():

    print(
        "\n"
        "========================================\n"
        "MFT Retrieval 회귀 테스트\n"
        "========================================"
    )

    print(
        "질문 수:",
        len(
            REGRESSION_QUESTIONS
        ),
    )

    print(
        "\n"
        "회귀 테스트는 LLM을 호출하지 않습니다.\n"
        "검색 후보 / Rank / Behavior가 "
        "다른 질문에서 깨지는지 확인합니다."
    )

    summaries = []

    for (
        question_number,
        query,
    ) in enumerate(

        REGRESSION_QUESTIONS,

        start=1,
    ):

        print(
            "\n\n"
            "########################################"
        )

        print(
            f"[TEST {question_number}]"
        )

        print(
            "질문:",
            query,
        )

        print(
            "########################################"
        )

        started = (
            time.perf_counter()
        )

        try:

            (
                points,
                plan,
                clusters,
            ) = (
                query_engine.retrieve(
                    query
                )
            )

        except Exception as exc:

            print(
                "\n[FAIL]"
            )

            print(
                type(
                    exc
                ).__name__,
                ":",
                exc,
            )

            summaries.append(
                {
                    "test":
                        question_number,

                    "status":
                        "FAIL",

                    "question":
                        query,

                    "error":
                        (
                            f"{type(exc).__name__}: "
                            f"{exc}"
                        ),
                }
            )

            continue

        finished = (
            time.perf_counter()
        )

        summary = (
            regression_result_summary(

                points,

                clusters,
            )
        )

        summary.update(
            {
                "test":
                    question_number,

                "status":
                    "OK",

                "question":
                    query,

                "mode":
                    plan.get(
                        "mode"
                    ),

                "intent":
                    plan.get(
                        "intent"
                    ),

                "topic":
                    plan.get(
                        "topic"
                    ),

                "behavior_query":
                    plan.get(
                        "behavior_query"
                    ),

                "elapsed":
                    (
                        finished
                        -
                        started
                    ),
            }
        )

        summaries.append(
            summary
        )

        print(
            "\n"
            "========================================\n"
            "TEST SUMMARY\n"
            "========================================"
        )

        print(
            "Mode:",
            summary[
                "mode"
            ],
        )

        print(
            "Intent:",
            summary[
                "intent"
            ],
        )

        print(
            "Topic:",
            summary[
                "topic"
            ],
        )

        print(
            "Behavior Query:",
            summary[
                "behavior_query"
            ],
        )

        print(
            "결과 수:",
            summary[
                "results"
            ],
        )

        print(
            "Behavior Cluster:",
            summary[
                "clusters"
            ],
        )

        print(
            "NTFS 내부 메타파일 결과:",
            summary[
                "ntfs_internal_in_results"
            ],
        )

        print(
            "Directory 결과:",
            summary[
                "directories_in_results"
            ],
        )

        print(
            "Normal Context 결과:",
            summary[
                "normal_context_results"
            ],
        )

        print(
            "System Reference 결과:",
            summary[
                "system_reference_results"
            ],
        )

        print(
            "처리시간:",
            f"{summary['elapsed']:.2f}s",
        )

        print(
            "\n상위 결과:"
        )

        for (
            rank,
            point,
        ) in enumerate(

            points[
                :10
            ],

            start=1,
        ):

            payload = (
                point.payload
                or {}
            )

            print(
                f"\n[{rank}]"
            )

            print(
                "File:",
                payload.get(
                    "file_name"
                ),
            )

            print(
                "Path:",
                payload.get(
                    "parent_path"
                ),
            )

            print(
                "Deleted:",
                payload.get(
                    "deleted"
                ),
            )

            print(
                "ExecOdd:",
                payload.get(
                    "exec_in_odd_place"
                ),
            )

            print(
                "Retrieval:",
                point.retrieval_reason,
            )

            print(
                "Record Features:",
                point.record_features,
            )

            print(
                "Cluster Features:",
                point.cluster_features,
            )

            print(
                "Normal Context:",
                point.normal_context_hint,
            )

            if (
                point.reference_paths
            ):

                print(
                    "System Reference:",
                    point.reference_paths,
                )

                print(
                    "Same Size:",
                    point.reference_same_size,
                )

        print(
            "\n상위 Behavior Cluster:"
        )

        for (
            cluster_rank,
            cluster,
        ) in enumerate(

            clusters[
                :5
            ],

            start=1,
        ):

            print(
                f"\n[{cluster_rank}]"
            )

            print(
                "Path:",
                cluster.get(
                    "path"
                ),
            )

            print(
                "Records:",
                cluster.get(
                    "record_count"
                ),
            )

            print(
                "Features:",
                cluster.get(
                    "cluster_features"
                ),
            )

            print(
                "First Activity:",
                cluster.get(
                    "first_activity"
                ),
            )

            print(
                "Last Activity:",
                cluster.get(
                    "last_activity"
                ),
            )

            print(
                "Time Span:",
                cluster.get(
                    "time_span_seconds"
                ),
            )

            print(
                "Burst Start:",
                cluster.get(
                    "burst_start"
                ),
            )

            print(
                "Burst End:",
                cluster.get(
                    "burst_end"
                ),
            )

            print(
                "Burst Count:",
                cluster.get(
                    "burst_count"
                ),
            )

            print(
                "Burst Span:",
                cluster.get(
                    "burst_span_seconds"
                ),
            )

            print(
                "Burst Density:",
                cluster.get(
                    "burst_density"
                ),
            )

            print(
                "Normal Context:",
                cluster.get(
                    "normal_context_hint"
                ),
            )

    print(
        "\n\n"
        "========================================\n"
        "회귀 테스트 전체 요약\n"
        "========================================"
    )

    for summary in summaries:

        if (
            summary[
                "status"
            ]
            ==
            "FAIL"
        ):

            print(
                f"[TEST {summary['test']}] "
                f"FAIL | "
                f"{summary['error']}"
            )

            continue

        print(
            f"[TEST {summary['test']}] "
            f"OK | "
            f"results="
            f"{summary['results']} | "
            f"clusters="
            f"{summary['clusters']} | "
            f"ntfs_internal="
            f"{summary['ntfs_internal_in_results']} | "
            f"directories="
            f"{summary['directories_in_results']} | "
            f"normal_context="
            f"{summary['normal_context_results']} | "
            f"system_reference="
            f"{summary['system_reference_results']} | "
            f"{summary['elapsed']:.2f}s"
        )


def rebuild():

    (
        pc_name,
        raw_csv,
    ) = (
        pipeline.select_csv()
    )

    print(
        "\nPC:",
        pc_name,
    )

    print(
        "원본:",
        raw_csv,
    )

    confirm = (
        input(
            "\n계속하려면 YES 입력: "
        )
        .strip()
    )

    if confirm != "YES":

        print(
            "취소"
        )

        return False

    slim_csv = (
        pipeline.run_mft_slim(

            pc_name,

            raw_csv,
        )
    )

    payload_jsonl = (
        pipeline.run_payload_conversion(
            slim_csv
        )
    )

    database.recreate_schema()

    database.ensure_dense_collection(
        reset=True
    )

    total = (
        database.ingest_jsonl(

            pc_name,

            payload_jsonl,
        )
    )

    database.create_indexes()

    actual = (
        database.get_db_count()
    )

    print(
        "\n"
        "========================================\n"
        "재구축 완료\n"
        "========================================"
    )

    print(
        "JSONL:",
        f"{total:,}",
    )

    print(
        "PostgreSQL:",
        f"{actual:,}",
    )

    print(
        "Dense Cache:",
        f"{database.get_dense_cache_count():,}",
    )

    if (
        total
        !=
        actual
    ):

        raise RuntimeError(
            "JSONL 처리 수와 "
            "PostgreSQL 행 수가 다릅니다."
        )

    return True


def main():

    print(
        """
========================================
MFT DFIR Pipeline
========================================

1 = 전체 재구축
2 = 기존 DB 검색
3 = Retrieval 회귀 테스트

검색 구조:

질문
 ↓
Sparse + Diversified Metadata
 ↓
(해당 시) System-name Reference
 ↓
Behavior Cluster / Neighbor 확장
 ↓
Dense 경로 다양화
 ↓
Weighted RRF
 ↓
Reranker
 ↓
LLM

중요:

- NTFS 내부 메타파일 레코드는 일반 MFT 검색에서 제외
- Behavior raw score는 악성도 점수가 아님
- Record 특징과 Cluster 특징 분리
- 특정 질문 하나만 맞추기보다 회귀 테스트로 전체 검색 품질 검증

========================================
"""
    )

    mode = (
        input(
            "선택: "
        )
        .strip()
    )

    if mode not in {
        "1",
        "2",
        "3",
    }:

        raise ValueError(
            "1, 2 또는 3 입력"
        )

    database.connect_all()

    check_services()

    if mode == "1":

        completed = (
            rebuild()
        )

        if not completed:

            return

        search_loop()

    elif mode == "2":

        if not (
            database
            .db_table_exists()
        ):

            raise RuntimeError(
                "기존 PostgreSQL DB가 없습니다."
            )

        database.ensure_dense_collection(
            reset=False
        )

        search_loop()

    elif mode == "3":

        if not (
            database
            .db_table_exists()
        ):

            raise RuntimeError(
                "기존 PostgreSQL DB가 없습니다."
            )

        database.ensure_dense_collection(
            reset=False
        )

        run_regression_tests()


if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print(
            "\n사용자 종료"
        )

    except Exception as exc:

        print(
            "\n"
            "========================================\n"
            "오류\n"
            "========================================"
        )

        print(
            type(
                exc
            ).__name__,
            ":",
            exc,
        )

        raise

    finally:

        database.close_all()
