# React2Shell Isolated Lab

이 프로젝트는 React Server Components 취약점인 **React2Shell
(CVE-2025-55182)** 동작을 확인하기 위한 Node.js/Next.js 격리 실습
환경입니다.

> [!WARNING]
> 의도적으로 취약한 버전을 사용합니다. 인터넷이나 업무망에 공개하지
> 말고, 명시적으로 허가된 폐쇄형 테스트 네트워크에서만 실행하십시오.
> 실제 계정, 운영 데이터, 클라우드 자격증명 및 기타 비밀정보를 이
> 서버에 저장하거나 전달하지 마십시오.

## 배포본 다운로드

- [react_server_was.zip](./react_server_was.zip)

ZIP에는 애플리케이션 소스, 고정된 패키지 정보, HTTP 로깅 스크립트와
버전 응답 헤더를 설정하는 `next.config.js`가 포함되어 있습니다.
`node_modules/`, `.next/`, 실행 로그는 포함되지 않습니다.

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

## 사전 준비

- Windows Server 2016 이상 또는 지원되는 Windows 환경
- Node.js 20 LTS x64 및 함께 설치되는 npm
- 서버에 실제로 할당된 고정 IP 주소
- 테스트 클라이언트에서 로깅 프록시 포트로 접근할 수 있는 격리망

압축 배포본을 사용할 때는 새로운 빈 디렉터리에 압축을 푸십시오.
이전 서버에서 생성된 `node_modules/`나 `.next/`를 복사해 사용하지
말고, 배포 대상 서버에서 아래 설치와 빌드 과정을 다시 수행하십시오.

## 환경변수

| 변수 | 기본값 | 설명 |
| --- | --- | --- |
| `REACT_LOGGER_HOST` | `192.168.223.143` | 테스트 클라이언트 요청을 받는 외부 로깅 프록시 주소 |
| `REACT_LOGGER_PORT` | `3000` | 외부 로깅 프록시 포트 |
| `REACT_UPSTREAM_HOST` | `127.0.0.1` | 내부 Next.js 서버 주소 |
| `REACT_UPSTREAM_PORT` | `3001` | 내부 Next.js 서버 포트 |
| `REACT_LOGGER_DIR` | 프로젝트의 `logs` 디렉터리 | JSONL 로그 저장 위치 |
| `REACT_LOGGER_MAX_CAPTURE_BYTES` | `10485760` | 요청 본문 최대 캡처 크기(바이트, 기본 10 MiB) |

`REACT_LOGGER_HOST`에는 실행 서버의 네트워크 인터페이스에 실제로
할당된 IP를 지정해야 합니다. 존재하지 않는 IP를 지정하면
`EADDRNOTAVAIL` 오류가 발생합니다. 모든 NIC에서 요청을 받도록
`0.0.0.0`을 사용할 수도 있지만, 노출 범위가 넓어지므로 격리된
실습망에서만 사용하십시오.

### 현재 CMD 창에서만 설정

다음 예시는 서버 IP가 `192.168.20.10`인 경우입니다.

```bat
set REACT_LOGGER_HOST=192.168.20.10
set REACT_LOGGER_PORT=3000
set REACT_UPSTREAM_HOST=127.0.0.1
set REACT_UPSTREAM_PORT=3001
```

### 현재 PowerShell 창에서만 설정

```powershell
$env:REACT_LOGGER_HOST = "192.168.20.10"
$env:REACT_LOGGER_PORT = "3000"
$env:REACT_UPSTREAM_HOST = "127.0.0.1"
$env:REACT_UPSTREAM_PORT = "3001"
```

### 사용자 환경변수로 영구 저장

CMD 또는 PowerShell에서 다음 명령을 실행합니다.

```bat
setx REACT_LOGGER_HOST "192.168.20.10"
setx REACT_LOGGER_PORT "3000"
setx REACT_UPSTREAM_HOST "127.0.0.1"
setx REACT_UPSTREAM_PORT "3001"
```

`setx`로 저장한 값은 현재 터미널에는 반영되지 않습니다. 터미널을
닫고 새로 연 다음 `echo %REACT_LOGGER_HOST%`로 확인하십시오. 모든
사용자 또는 서비스 계정에 시스템 환경변수로 등록하려면 관리자
터미널에서 각 `setx` 명령 끝에 `/M`을 추가합니다.

## 설치, 빌드 및 실행

Node.js와 npm이 설치된 격리 서버에서 다음 명령을 실행합니다.

```bat
cd C:\REACT_HOME\react_server_was
npm ci
npm run build
npm run start
```

환경변수 변경이나 `next.config.js` 수정 후에는 `npm run build`를
다시 실행해야 합니다. `npm run start`는 다음 두 프로세스를 함께
실행하며 포그라운드에서 동작합니다.

- HTTP 로깅 프록시: `REACT_LOGGER_HOST:REACT_LOGGER_PORT`
- 내부 Next.js 서버: `REACT_UPSTREAM_HOST:REACT_UPSTREAM_PORT`

테스트 클라이언트는 내부 Next.js 포트가 아니라 로깅 프록시 주소인
`http://<REACT_LOGGER_HOST>:<REACT_LOGGER_PORT>`로 접속합니다. 종료할
때는 실행 터미널에서 `Ctrl+C`를 누릅니다.

개별 프로세스 실행이 필요한 경우 다음 명령을 사용할 수 있습니다.

- `npm run start:next`: 내부 Next.js 서버만 실행
- `npm run logger`: HTTP 로깅 프록시만 실행

## Windows 방화벽과 접속 확인

관리자 PowerShell에서 실습망 대역에 한정해 인바운드 규칙을 만듭니다.
다음 예시는 서버가 `192.168.20.10`, 실습망이 `192.168.20.0/24`인
경우입니다.

```powershell
New-NetFirewallRule `
  -DisplayName "React2Shell Lab TCP 3000" `
  -Direction Inbound `
  -Action Allow `
  -Protocol TCP `
  -LocalAddress 192.168.20.10 `
  -LocalPort 3000 `
  -RemoteAddress 192.168.20.0/24 `
  -Profile Any
```

서버에서 리스닝 상태를 확인합니다.

```bat
netstat -ano | findstr :3000
```

다른 Windows PC에서 연결과 HTTP 응답을 확인합니다.

```powershell
Test-NetConnection 192.168.20.10 -Port 3000
Invoke-WebRequest http://192.168.20.10:3000 -UseBasicParsing
```

라우터 NAT, 클라우드 보안 그룹 또는 VLAN 정책은 Windows 방화벽과
별도로 적용됩니다. 이 실습 서버에 대한 인터넷 포트 포워딩은 하지
마십시오.

## 버전 응답 헤더 확인

`next.config.js`는 서버 응답에 설치된 Next.js, React 및 React DOM
버전을 표시합니다. 빌드 후 다음 명령으로 확인할 수 있습니다.

```powershell
(Invoke-WebRequest http://192.168.20.10:3000 -UseBasicParsing).Headers
```

고정된 현재 구성에서는 다음 헤더가 반환됩니다.

```text
X-Powered-By: Next.js/15.0.4 React/19.0.0
X-React-Version: 19.0.0
X-React-DOM-Version: 19.0.0
```

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

## 문제 해결

- `EADDRNOTAVAIL`: `REACT_LOGGER_HOST`가 서버에 실제로 할당된 IP인지
  `ipconfig`로 확인합니다.
- `EADDRINUSE`: 지정한 포트를 다른 프로세스가 사용 중입니다.
  `netstat -ano | findstr :3000`으로 PID를 확인하거나 포트를 변경합니다.
- 다른 PC에서 접속 불가: 서버의 리스닝 상태, Windows 방화벽 규칙,
  VLAN/라우팅 정책을 차례로 확인합니다.
- 버전 헤더가 보이지 않음: `next.config.js`가 프로젝트 루트에 있는지
  확인하고 `npm run build` 후 서버를 다시 시작합니다.
- 빌드 오류: 새로운 빈 디렉터리에 배포본을 다시 풀고 `npm ci`,
  `npm run build` 순서로 실행합니다. `npm update`나 `npm audit fix`는
  실행하지 않습니다.

## 포함하지 않는 파일

다음 항목은 서버에서 생성되거나 민감정보가 들어갈 수 있으므로
저장소에 올리지 않습니다.

- `node_modules/`
- `.next/`
- `logs/`
- `.env*`
- npm 디버그 로그
