import json
import requests

from config import *

HTTP = requests.Session()


def build_evidence(query, plan, points, clusters):
    records = []

    for point in points[:FINAL_RESULT_LIMIT]:
        payload = point.payload or {}

        records.append(
            {
                "record_id": point.id,
                "file_name": payload.get("file_name"),
                "parent_path": payload.get("parent_path"),
                "entry_number": payload.get("entry_number"),
                "file_size": payload.get("file_size"),
                "deleted": payload.get("deleted"),
                "created_si": payload.get("created_si"),
                "created_fn": payload.get("created_fn"),
                "modified_si": payload.get("modified_si"),
                "modified_fn": payload.get("modified_fn"),
                "record_change_si": payload.get("record_change_si"),
                "exec_in_odd_place": payload.get("exec_in_odd_place"),
                "persistence_place": payload.get("persistence_place"),
                "staging_archive": payload.get("staging_archive"),
                "tamper_target": payload.get("tamper_target"),
                "tags": payload.get("tags"),
                "retrieval_reason": point.retrieval_reason,
                "system_reference_paths": point.reference_paths,
                "system_reference_same_size": point.reference_same_size,
                "scores": {
                    "sparse": point.sparse_score,
                    "metadata": point.metadata_score,
                    "dense": point.dense_score,
                    "fused": point.fused_score,
                    "reranker": point.rerank_score,
                },
            }
        )

    evidence = {
        "question": query,
        "scope": "$MFT 단독 분석",
        "query_plan": plan,
        "records": records,
        "behavior_clusters": clusters[:12],
        "important_semantics": {
            "retrieval_score": "검색 관련성 점수이며 악성도 점수가 아니다.",
            "system_reference": (
                "동일 파일명이 System32/SysWOW64 reference 경로에도 존재한다는 뜻이다. "
                "해시 검증이 아니므로 실제 동일 바이너리 또는 정상 Windows 파일이라고 확정할 수 없다."
            ),
            "same_size": (
                "동일 파일명과 동일 크기 관계만 확인한 것이다. "
                "해시가 없으므로 동일 파일임을 의미하지 않는다."
            ),
            "behavior_cluster": (
                "실제 프로세스 실행 행위가 아니라 MFT에서 관찰되는 파일 활동 군집이다."
            ),
            "tamper_target": (
                "실제 변조 발생이 아니라 증거 훼손 대상이 될 수 있는 위치 범주이다."
            ),
        },
    }

    return json.dumps(
        evidence,
        ensure_ascii=False,
        indent=2,
        default=str,
    )


def ask_llm(query, plan, evidence):
    system_prompt = r"""
너는 Windows DFIR 조사에서 NTFS $MFT 증거를 분석하는 모델이다.
현재 입력 자료는 $MFT 단독이다.

[핵심 원칙]

1. Evidence에 직접 존재하는 사실과 추론을 분리한다.
2. 파일명만 보고 실제 프로그램 실행이나 공격 성공을 주장하지 않는다.
3. 검색 점수는 검색 관련성이지 악성도 점수가 아니다.
4. Behavior Cluster는 Retrieval 이후 주변 MFT 레코드에서 얻은 파일 활동 Context다.
5. 하나의 tag/flag 또는 파일명 하나만으로 공격을 확정하지 않는다.
6. 정상 가능성이 있는 Context도 반드시 검토한다.

[$MFT 단독 한계]

$MFT만으로 다음을 확정하지 않는다.

- 실제 프로세스 실행 여부
- 실제 명령 실행
- 권한 상승 성공
- Credential Dumping 수행
- 네트워크 연결
- 원격 제어 세션
- 데이터 유출
- 랜섬웨어 실제 실행 시각
- 랜섬웨어 암호화 시작 시각

예를 들어 Evidence에 mimikatz.exe, PrintSpoofer64.exe,
AnyDesk.exe 같은 이름이 있더라도 파일명만으로
Credential Dumping, 권한 상승, 원격 제어가 실제 수행됐다고 말하지 않는다.

허용되는 표현:
- "해당 이름의 파일 레코드가 관찰된다."
- "파일명/경로/군집상 추가 확인 가치가 있다."
- "실제 실행 여부는 다른 아티팩트 검증이 필요하다."

[SYSTEM_NAME_PATH_MISMATCH]

이 Intent는 동일한 file_name이 System32 또는 SysWOW64 reference 위치에 존재하면서,
별도의 비정상 위치에서도 같은 이름이 발견된 후보를 의미한다.

system_reference_same_size=true이면 이름과 크기까지 같은 reference가 존재한다.
그러나 hash 비교가 아니므로 같은 바이너리라고 확정하지 않는다.

이 질문에서는 일반적인 의심 파일을 나열하지 말고,
실제 system_name_path_mismatch 관계가 있는 후보를 중심으로 답한다.

[Behavior Cluster]

다음은 추가 조사 가치를 높일 수 있다.

- exe_plus_driver
- exe_plus_script
- archive_plus_executable
- odd_executable_cluster
- deleted_executable_cluster
- same_path_time_cluster

하지만 이것도 실제 실행을 의미하지 않는다.

normal_context_hint가 있으면 정상 소프트웨어/OS 동작 가능성을 함께 설명한다.

예:
- possible_windows_servicing
- possible_packaged_python_runtime

[TIMELINE]

Timestamp 하나를 실행 시각으로 해석하지 않는다.

TIMELINE 질문이면:
- created_si
- created_fn
- modified_si
- modified_fn
- record_change_si
- 관련 파일의 경로 군집
- 여러 파일의 시간 집중

을 함께 보고

"MFT 기준 의심 파일 활동 후보 구간"

정도로만 표현한다.

가장 오래된 Windows 기본 파일 timestamp 하나를 공격 시작 시점으로 사용하지 않는다.

[최종 응답 구조]

1. 질문에 대한 직접 결론
2. 핵심 Evidence
3. 높은 우선순위 후보
4. Behavior Cluster 해석
5. 정상 가능성이 높은 후보
6. $MFT 단독으로 확정할 수 없는 부분
7. 필요한 추가 검증 아티팩트

추가 검증 예:
- Prefetch
- Amcache
- Shimcache
- BAM/DAM
- Windows Event Log
- PowerShell Operational
- Defender Log
- SRUM
- $UsnJrnl
- $LogFile
- LNK
- Jump List

항상 한국어로 답한다.
"""

    user_prompt = f"""
[조사 질문]

{query}

[Query Mode]
{plan['mode']}

[Query Intent]
{plan['intent']}

[Topic]
{plan['topic']}

[분석 범위]
$MFT 단독 분석

[MFT Evidence]

{evidence}

[최종 요청]

조사 질문에 직접 답하라.

파일명만 보고 공격 행위나 실행 성공을 만들어내지 마라.
검색 결과 순위를 악성도 순위로 해석하지 마라.
Behavior Cluster는 파일 활동 Context로만 사용하라.

SYSTEM_NAME_PATH_MISMATCH 질문이라면
system_reference_paths가 실제 존재하는 후보 중심으로 답하라.

Evidence가 질문을 뒷받침하지 못하면
현재 $MFT Evidence만으로 판단할 수 없다고 명확하게 말하라.
"""

    response = HTTP.post(
        f"{OLLAMA_URL}/api/chat",
        json={
            "model": LLM_MODEL,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "keep_alive": "10m",
            "options": {
                "temperature": 0.03,
                "num_ctx": 8192,
            },
        },
        timeout=300,
    )

    response.raise_for_status()

    return (
        response.json()
        .get("message", {})
        .get("content", "")
    )
