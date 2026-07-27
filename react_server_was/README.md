# React2Shell Isolated Lab

이 프로젝트는 React Server Components 취약점인 **React2Shell
(CVE-2025-55182)** 동작을 확인하기 위한 Node.js/Next.js 격리 실습
환경입니다.

> [!WARNING]
> 의도적으로 취약한 버전을 사용합니다. 인터넷이나 업무망에 공개하지
> 말고, 명시적으로 허가된 폐쇄형 테스트 네트워크에서만 실행하십시오.
> 실제 계정, 운영 데이터, 클라우드 자격증명 및 기타 비밀정보를 이
> 서버에 저장하거나 전달하지 마십시오.

## 고정된 구성

- Next.js `15.0.4`
- React `19.0.0`
- React DOM `19.0.0`
- Next.js App Router
- React Server Action

React 공식 공지에 따르면 React `19.0.0`은 CVE-2025-55182 영향
버전입니다. Next.js App Router에 대한 하위 영향은
CVE-2025-66478로도 추적됩니다.

- React 공지:
  <https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components>
- Next.js 공지:
  <https://nextjs.org/blog/CVE-2025-66478>
- NVD:
  <https://nvd.nist.gov/vuln/detail/CVE-2025-55182>

## 의존성 업데이트 금지

취약 버전 재현을 위해 `package.json`의 버전과
`package-lock.json`을 고정했습니다.

- `npm update` 실행 금지
- `npm audit fix` 실행 금지
- `package.json` 및 `package-lock.json` 임의 변경 금지
- 설치할 때는 반드시 `npm ci` 사용

`npm ci`는 lockfile에 기록된 버전을 그대로 설치하며
`package.json`이나 `package-lock.json`을 갱신하지 않습니다.

## 빌드 및 실행

Node.js와 npm이 설치된 격리 서버에서 다음 명령을 실행합니다.

```bash
cd react_server_was
npm ci
npm run build
npm run start
```

`npm run start`는 다음 두 프로세스를 함께 실행합니다.

- HTTP 로깅 프록시: `192.168.223.143:3000`
- 내부 Next.js 서버: `127.0.0.1:3001`

테스트 클라이언트는 로깅 프록시인 `192.168.223.143:3000`으로
접속합니다. 실행 서버의 네트워크 인터페이스에
`192.168.223.143` 주소가 설정되어 있어야 합니다.

`npm run start`는 포그라운드에서 실행됩니다. 장기 실행이 필요하면
격리 환경의 서비스 관리자나 프로세스 관리 도구를 사용하십시오.

## HTTP 로깅

로깅 프록시는 요청을 내부 Next.js 서버로 전달하면서 다음 위치에
날짜별 JSONL 로그를 기록합니다.

```text
logs/http-requests-YYYY-MM-DD.jsonl
```

로그에는 연결 주소, HTTP 메서드와 URL, 요청 헤더, 원시 헤더,
요청 본문의 UTF-8 및 Base64 표현, 본문 SHA-256, 응답 상태와 크기,
처리 시간 및 오류가 포함됩니다. 기본 요청 본문 캡처 한도는
10 MiB입니다.

> [!CAUTION]
> 요청 헤더와 본문에는 쿠키, 인증 헤더, 세션 값 및 기타
> 민감정보가 포함될 수 있습니다. 합성 테스트 데이터만 사용하고,
> 로그 디렉터리의 접근 권한과 보존 기간을 제한하십시오.
> `logs/`는 Git 업로드 대상에서 제외되어 있습니다.

환경변수로 기본값을 변경할 수 있습니다.

- `REACT_LOGGER_HOST`, `REACT_LOGGER_PORT`: 외부 로깅 프록시 주소
- `REACT_UPSTREAM_HOST`, `REACT_UPSTREAM_PORT`: 내부 Next.js 주소
- `REACT_LOGGER_DIR`: JSONL 로그 디렉터리
- `REACT_LOGGER_MAX_CAPTURE_BYTES`: 요청 본문 최대 캡처 크기

개별 실행이 필요한 경우 다음 스크립트를 사용할 수 있습니다.

- `npm run start:next`: 내부 Next.js 서버만 실행
- `npm run logger`: HTTP 로깅 프록시만 실행

## 포함하지 않는 파일

다음 항목은 서버에서 생성되거나 민감정보가 들어갈 수 있으므로
저장소에 올리지 않습니다.

- `node_modules/`
- `.next/`
- `logs/`
- `.env*`
- npm 디버그 로그
