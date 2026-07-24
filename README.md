# Tiny Market

보안을 설계 단계부터 반영한 교육용 소규모 중고거래 플랫폼입니다. 회원, 상품, 채팅, 신고·차단, 가상 포인트 송금, 관리자 통합 관리라는 과제의 최소 요구사항을 모두 구현했습니다.

> 이 저장소의 송금 기능은 실제 금융 기능이 아닌 교육용 가상 포인트 원장입니다.

## 구현 기능

| 요구사항 | 구현 |
|---|---|
| 가입·로그인·프로필 | 중복 없는 아이디, scrypt 비밀번호 해시, 소개글·비밀번호 수정 |
| 상품 등록·조회 | 상품명·설명·가격·이미지, 판매 상태, 본인 상품 수정·삭제 |
| 상품 검색 | 상품명·설명 검색, SQL 와일드카드 이스케이프 |
| 사용자 소통 | 3초 폴링 기반 전체 채팅과 1:1 채팅 |
| 악성 대상 차단 | 개인 사용자 차단, 사용자·상품 신고, 3인 신고 시 자동 차단, 관리자 재검토 |
| 사용자 간 송금 | 가상 포인트, 비밀번호 재확인, 원자적 잔액 변경, 중복 요청 방지, 원장 보존 |
| 관리자 전체 관리 | 사용자·상품·신고·메시지 관리, 송금 원장과 감사 로그 조회 |

## 기술 구성

- Python 3.11 이상
- Flask 3.1 계열
- SQLite 3
- Jinja 템플릿과 순수 JavaScript/CSS
- Pillow 기반 안전한 이미지 재인코딩
- pytest, Bandit, pip-audit

SQLite를 사용해 별도 데이터베이스 서버 없이 평가 환경에서 바로 실행할 수 있습니다. 모든 SQL 값은 파라미터로 바인딩하며, 데이터베이스 제약조건과 애플리케이션 검증을 함께 사용합니다.

## 환경 설정 및 실행

Ubuntu/WSL 기준입니다.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m flask --app app init-db
python -m flask --app app create-admin
python -m flask --app app run
```

브라우저에서 `http://127.0.0.1:5000`에 접속합니다. 일반 회원은 가입 시 교육용 포인트 100,000원을 받습니다. 관리자 계정은 기본 비밀번호를 제공하지 않으며 `create-admin` 명령에서 직접 안전한 비밀번호를 설정합니다.

데이터베이스와 업로드 파일은 기본적으로 `instance/`에 저장되고 Git에서 제외됩니다. 개발 환경에서는 `instance/secret_key`가 최초 실행 시 안전한 난수로 생성됩니다.

### 환경변수

| 변수 | 기본값 | 설명 |
|---|---|---|
| `APP_ENV` | `development` | `production`이면 HTTPS 전용 쿠키와 HSTS 활성화 |
| `SECRET_KEY` | 개발 시 로컬 난수 파일 | 운영에서는 32자 이상의 난수 필수 |
| `DATABASE` | `instance/marketplace.sqlite3` | SQLite 파일 경로 |
| `UPLOAD_FOLDER` | `instance/uploads` | 재인코딩된 이미지 저장 경로 |

운영 설정 예시는 다음과 같습니다. `.env.example`은 참고용이며, 셸에 직접 로드해야 합니다.

```bash
cp .env.example .env
# .env의 SECRET_KEY를 안전한 난수로 변경
set -a
source .env
set +a
python -m flask --app app run
```

운영 배포에서는 Flask 개발 서버를 외부에 노출하지 말고, TLS가 설정된 리버스 프록시 뒤의 WSGI 서버를 사용해야 합니다.

## 테스트와 보안 점검

개발 의존성을 설치한 뒤 실행합니다.

```bash
pip install -r requirements-dev.txt
pytest -q
bandit -r marketplace app.py
pip-audit -r requirements.txt
```

2026-07-22 기준 결과:

- pytest: 20 passed
- Bandit: Low/Medium/High 이슈 0건, `# nosec` 예외 0건
- pip-audit: 알려진 취약점 0건

검증 범위는 [보안 체크리스트](docs/SECURITY_CHECKLIST.md)에 정리했습니다.

## 주요 보안 통제

- scrypt와 사용자별 난수 salt를 적용하고 평문 비밀번호를 저장하거나 기록하지 않습니다.
- 모든 상태 변경 요청에 세션 기반 CSRF 토큰을 검증합니다.
- 로그인 후 세션과 CSRF 토큰을 회전하고 `HttpOnly`, `SameSite=Lax`, 운영 `Secure` 쿠키를 사용합니다.
- 모든 SQL 값을 `?` 파라미터로 바인딩하며 검색 와일드카드도 이스케이프합니다.
- 객체 소유권과 관리자 역할을 서버에서 매 요청 검사해 IDOR를 차단합니다.
- Jinja 자동 이스케이프와 `textContent`, CSP를 함께 사용해 XSS를 방어합니다.
- 업로드 파일은 크기·픽셀 수·실제 이미지 형식을 확인하고 서버에서 재인코딩한 뒤 UUID 이름으로 저장합니다. SVG는 허용하지 않습니다.
- 송금은 `BEGIN IMMEDIATE`, 조건부 잔액 차감, 재인증, 요청별 nonce와 원장을 사용합니다.
- 로그인·회원가입·메시지·신고·송금에는 SQLite 기반 속도 제한을 적용합니다.
- 관리자 변경과 중요 사용자 행위를 감사 로그에 기록합니다.

## 프로젝트 구조

```text
app.py                       Flask 진입점
marketplace/
  __init__.py                설정, 보안 헤더, 오류 처리, CLI
  auth.py                    인증과 프로필
  market.py                  상품, 채팅, 신고·차단, 송금
  admin.py                   관리자 RBAC와 관리 기능
  db.py / schema.sql         DB 연결과 스키마
  security.py                해시, CSRF, 검증, 업로드, 속도 제한
  templates/ / static/       화면과 안전한 폴링 코드
tests/                       기능·보안 자동화 테스트 20개
docs/                        보고서 원본과 보안 체크리스트
scripts/generate_report.py   제출 형식 PDF 생성기
```

## 보고서 생성

아래 값은 본인 정보와 실제 공개 저장소 주소로 입력합니다. 결과 파일명에는 공백이 들어가지 않습니다.

```bash
python scripts/generate_report.py \
  --class-number 01 \
  --name 홍길동 \
  --phone-last4 1234 \
  --github-url https://github.com/your-id/secure-coding
```

생성 파일: `[WHS][secure-coding][01반]홍길동(1234).pdf`

## GitHub 공개 저장소 게시

강의 자료의 절차에 따라 GitHub 인증 후 다음과 같이 게시할 수 있습니다. 원본 강의 PDF, 로컬 DB, 비밀키, 업로드 파일은 `.gitignore`로 제외됩니다.

```bash
git init
git add .
git commit -m "Implement secure Tiny Market"
gh auth login
gh repo create secure-coding --public --source=. --remote=origin --push
```

게시 후 실제 저장소 URL을 사용해 보고서를 다시 생성하고, 저장소 공개 여부와 README 화면을 로그아웃 상태에서 확인합니다.

## 알려진 한계와 유지보수

- 채팅은 단일 서버에 적합한 3초 폴링 방식입니다. 대규모 환경에서는 WebSocket과 메시지 브로커가 필요합니다.
- SQLite와 로컬 업로드는 단일 인스턴스용입니다. 확장 시 PostgreSQL과 객체 저장소로 이전해야 합니다.
- 3인 자동 차단은 빠른 피해 억제를 위한 교육용 정책입니다. 다중 계정 악용에 대비해 운영에서는 계정 신뢰도와 관리자 검토를 결합해야 합니다.
- 실제 금융 기능으로 확장하려면 전자금융 규정, 강한 사용자 인증, 이중 원장, 정산·환불·분쟁 처리가 별도로 필요합니다.

자세한 개발 과정, 위협 모델, 수정한 보안 약점, 테스트 결과와 유지보수 계획은 [보고서 원본](docs/REPORT.md)에 있습니다.
