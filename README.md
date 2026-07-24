# 되살림 — Tiny Second-hand Shopping Platform

되살림은 물건을 등록·검색하고, 이웃과 채팅하고, 신고·송금할 수 있는 중고거래 웹 플랫폼입니다. `secure-coding-slide.v2.pdf`의 최소 요구사항과 25~28페이지의 시스템 설계를 기준으로 구현했습니다.

과제 보고서는 docs/report에 있습니다
.
## 구현 기능

| 요구사항 | 구현 내용 |
| --- | --- |
| 사용자 관리 | 회원가입, 로그인, 사용자 조회, 프로필, 소개글·비밀번호 변경, 아이디 중복 방지 |
| 상품 관리 | 사진 업로드, 등록·수정·삭제, 전체 조회, 상세 페이지, 내 상품 관리, 검색 |
| 사용자 소통 | Server-Sent Events 기반 실시간 전체 채팅, 1대1 채팅 |
| 신고 및 차단 | 사용자·상품 신고, 중복 신고 방지, 3회 누적 시 임시 제한 및 관리자 검토 |
| 송금 | 관리자 잔액 지급, 비밀번호 재확인, 중복 요청 방지, 송금 기록, 잔액·동시성 검증 |
| 관리자 | 사용자 휴면·복구, 잔액 지급, 상품 삭제·복구, 신고 검토, 채팅 삭제, 송금 조회 |
| 데이터베이스 | 사용자, 상품, 신고, 채팅, 송금, 세션, 감사 로그를 SQLite로 관리 |

## 실행 환경

- Python 3.12
- Jinja2 3.1.6
- Pillow 12.3.0
- SQLite 3
- 최신 Chrome, Edge, Firefox 또는 Safari

Node.js나 별도의 데이터베이스 서버는 필요하지 않습니다.

## 설치 및 실행

Ubuntu 또는 WSL 터미널에서 저장소 폴더로 이동한 후 실행합니다.

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

관리자 비밀번호를 환경 변수로 지정하고 서버를 실행합니다.

```bash
export ADMIN_PASSWORD='충분히-긴-관리자-비밀번호'
python3 app.py --seed
```

브라우저에서 <http://127.0.0.1:8000>으로 접속합니다.

- `--seed`는 화면 확인용 사용자·상품·채팅을 한 번만 추가합니다.
- 데모 사용자 아이디는 `demo_seller`, `demo_buyer`이며 비밀번호는 최초 실행 시 터미널에 한 번 출력됩니다.
- `--seed`를 사용하지 않으면 데모 계정과 상품을 생성하지 않습니다.
- `ADMIN_PASSWORD`를 생략하면 안전한 임의 비밀번호를 생성해 최초 실행 시 터미널에 한 번 출력합니다.

### 주요 실행 옵션

```bash
python3 app.py --help
python3 app.py --host 0.0.0.0 --port 8080
python3 app.py --init-only
```

## 테스트

전체 단위·통합 테스트를 실행합니다.

```bash
python3 -m unittest discover -s tests -v
```

테스트에는 다음 항목이 포함됩니다.

- 비밀번호 해시 및 정책
- 아이디 형식 검증과 요청 횟수 제한
- 데이터베이스 제약조건과 초기화 멱등성
- 서버 재시작 후에도 유지되는 요청 횟수 제한
- 회원가입 → 상품 등록 → 송금 → 전체 채팅 → 신고 흐름
- 신규 사용자 초기 잔액 0원 및 관리자 잔액 지급
- 서로 다른 사용자 3명의 신고 누적에 따른 임시 차단, 관리자 복구 및 미처리 신고 재집계
- 이미지 완전 디코딩·재인코딩, 해상도 제한 및 EXIF 제거
- 비밀번호 변경 시 세션 토큰 교체
- 휴면 사용자 상품과 업로드 이미지 공개 접근 차단
- 송금 비밀번호 재확인과 동일 요청 중복 처리 차단
- 관리자 TOTP 2차 인증
- 신뢰 프록시의 전달 IP 검증
- CSRF 검증과 미인증 사용자의 상품 삭제 차단
- 보안 응답 헤더
- 관리자 접근과 채팅 관리

## 환경 변수

| 이름 | 기본값 | 설명 |
| --- | --- | --- |
| `ADMIN_USERNAME` | `admin` | 최초 관리자 아이디 |
| `ADMIN_PASSWORD` | 개발 환경에서 임의 생성 | 최초 관리자 비밀번호. 운영 모드의 최초 실행에서는 보안 정책을 만족하는 값 필수 |
| `ADMIN_TOTP_SECRET` | 없음 | 관리자 TOTP용 Base32 비밀키. 운영 모드에서는 160비트 이상 필수 |
| `DEMO_PASSWORD` | 임의 생성 | 로컬 데모 계정 비밀번호. 12자 이상 |
| `MARKET_DB_PATH` | `instance/market.db` | SQLite 데이터베이스 경로 |
| `MARKET_UPLOAD_DIR` | `instance/uploads` | 상품 이미지 저장 경로 |
| `HOST` | `127.0.0.1` | 서버 바인딩 주소 |
| `PORT` | `8000` | 서버 포트 |
| `SEED_DEMO_DATA` | `0` | `1`이면 데모 데이터 생성 |
| `COOKIE_SECURE` | `0` | HTTPS 운영 환경에서는 `1`로 설정 |
| `APP_ENV` | `development` | `production`이면 보안 쿠키·HSTS를 강제하고 데모 데이터 생성을 차단 |
| `TRUSTED_PROXY_IPS` | 없음 | 전달 IP 헤더를 신뢰할 역방향 프록시 IP 목록. 쉼표로 구분 |

## 데이터베이스 설계

```text
users ──< products
  │
  ├──< messages >── users
  ├──< reports
  ├──< transfers >─ users
  ├──< sessions
  └──< audit_logs
```

- `users`: 아이디, 계정명, 비밀번호 해시, 소개글, 역할, 상태, 가상 잔액
- `products`: 상품명, 설명, 가격, 사진 경로, 판매자, 상태, 신고 횟수
- `messages`: 발신자, 수신자(전체 채팅은 `NULL`), 본문
- `reports`: 신고자, 대상 유형, 대상 아이디, 사유, 처리 상태
- `transfers`: 보낸 사용자, 받은 사용자, 금액, 메모, 중복 방지 토큰 해시
- `sessions`: 해시 처리된 세션 토큰과 만료 시각
- `audit_logs`: 관리자 조치 및 중요 변경 이력
- `request_events`: 요청 제한 유형, 식별자 해시와 요청 시각

## 보안 설계

- 비밀번호는 무작위 salt를 사용한 `scrypt` 해시로만 저장합니다.
- 세션 원문은 쿠키에만 두고 데이터베이스에는 SHA-256 해시를 저장합니다.
- 세션 쿠키에 `HttpOnly`, `SameSite=Lax`를 적용하고 운영 모드에서는 `Secure`를 강제합니다.
- 모든 상태 변경 요청에 예측 불가능한 CSRF 토큰을 검증합니다.
- Jinja2 자동 이스케이프와 클라이언트 `textContent`를 사용해 사용자 입력을 출력합니다.
- 모든 SQL 값은 매개변수 바인딩을 사용합니다.
- 상품 수정·삭제, 관리자 조치, 1대1 채팅에 서버 측 권한 검사를 적용합니다.
- 로그인과 메시지 전송에 요청 횟수 제한을 적용합니다.
- 회원가입·로그인·신고·메시지 제한 기록을 SQLite에 저장해 재시작 후에도 유지합니다.
- 이미지 크기, 파일 구조, 해상도를 검증하고 PNG, JPEG, WebP만 허용합니다.
- 사용자당 상품 수를 제한하고 교체·삭제된 이미지를 저장소에서 제거합니다.
- 업로드 이미지는 Pillow로 완전히 디코딩한 뒤 재인코딩하여 EXIF·GPS 등 메타데이터를 제거합니다.
- 휴면 사용자나 차단된 상품의 상세 페이지와 업로드 이미지 공개 접근을 거부합니다.
- 송금은 비밀번호를 다시 확인하고 일회성 요청 토큰, `BEGIN IMMEDIATE` 트랜잭션과 조건부 잔액 차감으로 처리합니다.
- 중복 신고를 데이터베이스 `UNIQUE` 제약조건으로 막습니다.
- 가입 후 1시간이 지난 계정만 신고할 수 있으며 신고 횟수도 제한합니다.
- 관리자 처리 후에는 새로 접수된 미처리 신고만 차단 횟수에 포함합니다.
- 사용자 휴면 시 기존 로그인 세션을 모두 삭제합니다.
- 로그인 시 기존 세션을 폐기하고 새로운 세션을 발급합니다.
- 비밀번호를 변경한 후에는 현재 세션도 새 토큰으로 교체합니다.
- 운영 모드에서는 관리자 계정에 TOTP 2차 인증을 강제합니다.
- 전체 채팅은 인증된 사용자만 연결하며 IP별·서버 전체 연결 수를 제한합니다.
- 전달 IP는 `TRUSTED_PROXY_IPS`에 등록된 프록시에서 온 경우에만 사용합니다.
- 운영 데이터베이스는 `600`, 데이터·업로드 폴더는 `700` 권한인지 검사합니다.
- CSP, 클릭재킹 방지, MIME 스니핑 방지 등 보안 응답 헤더를 전송합니다.
- 중요한 사용자·상품·송금·관리 작업은 감사 로그에 남깁니다.

## 요구사항 결정 사항

PDF 안에서 구체적으로 정해지지 않았거나 서로 다른 부분은 다음과 같이 설계했습니다.

- 상품 목록에는 상품명뿐 아니라 별도로 요구된 가격과 사진도 함께 표시합니다.
- 상품 사진은 데이터베이스에 파일 자체가 아닌 안전하게 생성한 파일 경로로 저장합니다.
- 신고 대상은 `target_type`과 `target_id` 조합으로 사용자와 상품을 구분합니다.
- 상품과 사용자는 서로 다른 사용자의 신고 3회가 누적되면 임시 제한되며 관리자가 유지 또는 복구를 결정합니다.
- 실제 결제 시스템 대신 과제 시연용 가상 잔액을 사용합니다. 신규 사용자의 잔액은 0원이며 관리자가 필요한 금액을 지급합니다.
- 관리자 화면은 사용자·상품·신고·채팅을 관리하고 송금 내역을 조회할 수 있습니다.

## 프로젝트 구조

```text
.
├── app.py                      # HTTP 서버, 라우팅, 권한 및 입력 검증
├── marketplace/
│   ├── db.py                   # 스키마, 초기화, 데모 데이터, 감사 로그
│   └── security.py             # 비밀번호, 토큰, 입력 정책, 요청 제한
├── templates/                  # Jinja2 화면 템플릿
├── static/                     # CSS, JavaScript, 로컬 SVG
├── instance/
│   └── uploads/                # 업로드 이미지(버전 관리 제외)
├── tests/                      # 단위 및 HTTP 통합 테스트
├── REQUIREMENTS_CHECKLIST.md   # 과제 요구사항 체크리스트
└── requirements.txt
```

## 운영 및 유지보수 시 주의사항

현재 구현은 과제 시연과 단일 서버 실행을 위한 버전입니다.

- 인터넷에 공개할 때는 HTTPS 역방향 프록시 뒤에서 `APP_ENV=production`, `COOKIE_SECURE=1`, `ADMIN_TOTP_SECRET`을 설정해야 합니다.
- `ADMIN_TOTP_SECRET`은 인증 앱에 같은 Base32 비밀키를 수동 등록해야 하며 저장소에 커밋하면 안 됩니다.
- 역방향 프록시가 전달 헤더를 덮어쓰도록 설정한 후 해당 프록시 IP만 `TRUSTED_PROXY_IPS`에 등록합니다.
- 운영 데이터는 OneDrive 경로가 아닌 권한을 `700`으로 제한할 수 있는 전용 Linux 폴더에 저장합니다.
- `--seed`로 만든 데모 계정은 공개 운영 환경에서 사용하지 않습니다.
- `instance/market.db`와 `instance/uploads`를 함께 정기 백업해야 합니다.
- 여러 서버 인스턴스로 확장할 때는 SQLite 기반 요청 제한과 로컬 업로드를 외부 데이터베이스·공용 저장소로 교체해야 합니다.
- 되살림페이는 실제 금융 결제가 아닌 과제 시연용 가상 송금입니다.

### 운영 모드 예시

먼저 TOTP용 비밀키를 생성하고 인증 앱에 같은 값을 등록합니다.

```bash
export TOTP_SECRET="$(python3 -c 'import base64,secrets; print(base64.b32encode(secrets.token_bytes(20)).decode())')"
echo "$TOTP_SECRET"
```

```bash
export APP_ENV=production
export COOKIE_SECURE=1
export ADMIN_PASSWORD='보안-정책을-만족하는-최초-관리자-비밀번호'
export ADMIN_TOTP_SECRET="$TOTP_SECRET"
export MARKET_DB_PATH='/srv/resalim-data/market.db'
export MARKET_UPLOAD_DIR='/srv/resalim-data/uploads'
export TRUSTED_PROXY_IPS='127.0.0.1'
python3 app.py
```

## GitHub 제출 전 확인

1. 본인 GitHub에 공개 저장소를 생성합니다.
2. 이 프로젝트를 업로드합니다.
3. 실제 저장소 주소를 최종 PDF 보고서에 포함합니다.
4. `ADMIN_PASSWORD`, 데이터베이스, 업로드 파일 등 운영 데이터가 커밋되지 않았는지 확인합니다.
