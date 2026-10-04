# QuantumSafe-IDS

An intrusion detection system (IDS) project written in Python. This guide explains how to clone the repository and run it on **Windows using WSL** (Windows Subsystem for Linux).

---

## Repository layout

```
quantumsafe-ids/
├── configs/              # Configuration files
├── data/                 # Datasets and data files
├── docker/               # Dockerfiles and container resources
├── models/               # Trained / baseline models
├── reports/              # Generated reports and results
├── scripts/              # Helper and utility scripts
├── src/                  # Main source code
├── tests/                # Test suite (pytest)
├── .env.example          # Template for environment variables
├── docker-compose.yml    # Multi-container setup
├── KNOWN_LIMITATIONS.md  # Known limitations of the project
└── README.md
```

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Windows 10 (2004+) or Windows 11 | With virtualization enabled |
| WSL 2 with Ubuntu | Installed in Step 1 |
| Python 3.10+ | Installed inside WSL |
| Git | Installed inside WSL |
| Docker Desktop (optional) | Only needed to run via `docker-compose` |

---

## 1. Install WSL (first time only)

Open **PowerShell as Administrator** and run:

```powershell
wsl --install -d Ubuntu
```

Restart your PC if prompted, then open **Ubuntu** from the Start menu and create your Linux username and password.

Check that you are on WSL 2:

```powershell
wsl -l -v
```

---

## 2. Prepare the WSL environment

Inside the Ubuntu (WSL) terminal:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git python3 python3-pip python3-venv build-essential
```

Verify:

```bash
git --version
python3 --version
```

Configure git (first time only):

```bash
git config --global user.name "Your Name"
git config --global user.email "you@example.com"
```

---

## 3. Clone the repository

> **Tip:** Clone into your Linux home folder (`~`), not `/mnt/c/...`. It is much faster and avoids file-permission and line-ending problems.

**Using HTTPS:**

```bash
cd ~
git clone https://github.com/sreenugopireddy/quantumsafe-ids.git
cd quantumsafe-ids
```

**Using SSH** (if you have set up an SSH key with GitHub):

```bash
cd ~
git clone git@github.com:sreenugopireddy/quantumsafe-ids.git
cd quantumsafe-ids
```

---

## 4. Create a virtual environment and install dependencies

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
```

Install the project requirements. Use whichever file the project provides:

```bash
# If a requirements file exists
pip install -r requirements.txt

# If the project uses pyproject.toml / setup.py
pip install -e .
```

Your prompt should now start with `(venv)`.

To activate the environment again later:

```bash
cd ~/quantumsafe-ids
source venv/bin/activate
```

---

## 5. Configure environment variables

Copy the example file and edit it:

```bash
cp .env.example .env
nano .env
```

Fill in the values. **Never commit `.env`**. It is listed in `.gitignore` and may contain secrets.

---

## 6. Run the project

Run the main application or the scripts in `scripts/`. List what is available:

```bash
ls scripts/
ls src/
```

Typical ways to start the project:

```bash
# Run a script
python scripts/<script_name>.py

# Run a module from src
python -m src.<module_name>
```

Replace `<script_name>` and `<module_name>` with the entry points in your project.

---

## 7. Run the tests

```bash
source venv/bin/activate
pip install pytest      # if not already installed
pytest tests/ -v
```

Run a single test file:

```bash
pytest tests/test_example.py -v
```

---

## 8. Run with Docker (optional)

1. Install [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop/).
2. In Docker Desktop, go to **Settings → Resources → WSL Integration** and enable your Ubuntu distro.
3. In the WSL terminal:

```bash
cd ~/quantumsafe-ids
docker --version
docker compose up --build
```

Run in the background:

```bash
docker compose up -d --build
```

View logs and stop the services:

```bash
docker compose logs -f
docker compose down
```

---

## Troubleshooting

**`python3 -m venv` fails with "ensurepip is not available"**

```bash
sudo apt install -y python3-venv
```

**`Permission denied (publickey)` when cloning over SSH**

```bash
ssh -T git@github.com
```

If this fails, add your SSH key to GitHub (Settings → SSH and GPG keys), or clone with the HTTPS URL instead.

**HTTPS asks for a password and fails**

GitHub no longer accepts account passwords. Use a Personal Access Token as the password, or log in with the GitHub CLI:

```bash
sudo apt install -y gh
gh auth login
```

**`fatal: detected dubious ownership in repository`**

```bash
git config --global --add safe.directory "$(pwd)"
```

**Line-ending warnings (CRLF vs LF)**

```bash
git config --global core.autocrlf input
```

**Docker command not found in WSL**

Make sure Docker Desktop is running and WSL Integration is enabled for your distro (see Step 8).

**Package build errors during `pip install`**

```bash
sudo apt install -y build-essential python3-dev
```

---

## Updating your copy

```bash
cd ~/quantumsafe-ids
git pull origin main
source venv/bin/activate
pip install -r requirements.txt
```

---

## Known limitations

See [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).

---

## Author

[sreenugopireddy](https://github.com/sreenugopireddy)
