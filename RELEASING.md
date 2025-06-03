# Release Process for AWS Bedrock Security Checker

This document describes the automated release process for the bedrock-security-checker package.

## 🚀 Automated Release Options

### Option 1: GitHub Actions (Recommended)

Once you set up the GitHub secrets, releases are fully automated:

1. **Setup (one-time)**:
   - Go to your GitHub repo → Settings → Secrets and variables → Actions
   - Add secret `PYPI_API_TOKEN` with your PyPI API token
   - (Optional) Add `TEST_PYPI_API_TOKEN` for test releases

2. **Automatic Release on Tag**:
   ```bash
   # Update version in setup.py and pyproject.toml
   git add setup.py pyproject.toml
   git commit -m "Release version X.Y.Z"
   git tag vX.Y.Z
   git push origin main --tags
   ```
   GitHub Actions will automatically build and publish to PyPI.

3. **Manual Trigger**:
   - Go to Actions tab → "Publish to PyPI" workflow
   - Click "Run workflow"

### Option 2: Local Release Script

Use the included `release.sh` script for interactive releases:

```bash
./release.sh
```

This script will:
- Auto-increment version (or ask for new version)
- Update version in all files
- Create git commit and tag
- Build the package
- Optionally push to git
- Optionally publish to PyPI

### Option 3: Makefile Commands

Quick commands for common tasks:

```bash
# Full release process
make release

# Just bump version and commit
make bump-patch  # 1.0.1 → 1.0.2
make bump-minor  # 1.0.1 → 1.1.0
make bump-major  # 1.0.1 → 2.0.0

# Build and publish manually
make build
make publish
```

## 📋 Manual Release Steps

If you prefer manual control:

1. **Update Version**:
   ```bash
   # Edit version in setup.py and pyproject.toml
   vim setup.py pyproject.toml
   ```

2. **Commit and Tag**:
   ```bash
   git add setup.py pyproject.toml
   git commit -m "Release version X.Y.Z"
   git tag -a vX.Y.Z -m "Version X.Y.Z"
   ```

3. **Build**:
   ```bash
   make clean
   python -m build
   ```

4. **Upload to PyPI**:
   ```bash
   python -m twine upload dist/*
   ```

5. **Push to GitHub**:
   ```bash
   git push origin main --tags
   ```

## 🔑 PyPI Token Setup

1. Go to https://pypi.org/manage/account/token/
2. Create a new API token
3. Save it securely

For automation:
- **GitHub Actions**: Add as repository secret `PYPI_API_TOKEN`
- **Local**: Create `~/.pypirc`:
  ```ini
  [pypi]
  username = __token__
  password = pypi-AgEIcHlwaS5vcmc...your-token-here
  ```

## 🧪 Testing Releases

Before releasing to production PyPI:

1. **Test on Test PyPI**:
   ```bash
   python -m twine upload --repository testpypi dist/*
   pip install --index-url https://test.pypi.org/simple/ bedrock-security-checker
   ```

2. **Local Testing**:
   ```bash
   pip install -e .
   bedrock-security-checker --help
   ```

## 📝 Release Checklist

- [ ] All tests pass
- [ ] Version updated in setup.py and pyproject.toml
- [ ] README.md is up to date
- [ ] CHANGELOG updated (if maintaining one)
- [ ] Git commit and tag created
- [ ] Package builds without warnings
- [ ] Package uploads successfully
- [ ] Installation works: `pip install bedrock-security-checker`

## 🚨 Troubleshooting

### "Version already exists" Error
- Increment the version number
- Delete the tag if needed: `git tag -d vX.Y.Z`

### Authentication Failed
- Check your PyPI token is valid
- Ensure token has upload permissions
- For GitHub Actions, check secret name matches

### Build Warnings
- Run `python -m twine check dist/*` to see issues
- Common: License format warnings (can be ignored)

---

**Built with 🧪👽 by ET**