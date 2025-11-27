# Deployment Recommendations for wafrunner-cli

## Current State Analysis

✅ **Already Configured:**
- `pyproject.toml` with proper metadata
- Entry point defined: `wafrunner = "wafrunner_cli.main:app"`
- Dependencies specified
- Modern Python packaging (setuptools backend)
- Test suite (54 tests passing)
- Linting/formatting setup

⚠️ **Needs Improvement:**
- Version is hardcoded at `0.0.1` (should be dynamic)
- No build/CI/CD pipeline for releases
- No PyPI publishing configuration
- Missing classifiers, keywords, URLs in metadata
- No version management strategy

## Recommended Deployment Strategy

### Option 1: PyPI (Public) - **RECOMMENDED for Release Candidate**

**Pros:**
- Standard Python distribution method
- Easy installation: `pip install wafrunner-cli`
- Automatic dependency resolution
- Version management via PyPI
- Works with virtual environments
- Can publish to TestPyPI first for validation

**Cons:**
- Requires PyPI account setup
- Public visibility (unless using private PyPI)
- Requires proper versioning strategy

**Implementation Steps:**

1. **Update `pyproject.toml` with complete metadata:**
```toml
[project]
name = "wafrunner-cli"
version = "0.1.0rc1"  # Use semantic versioning
description = "Command Line Interface for the wafrunner security testing platform"
readme = "README.md"
requires-python = ">=3.8"
license = {text = "MIT"}  # Or your license
authors = [
    {name = "wafrunner", email = "support@wafrunner.com"},
]
maintainers = [
    {name = "wafrunner", email = "support@wafrunner.com"},
]
keywords = ["security", "waf", "testing", "vulnerability", "cli"]
classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Developers",
    "Intended Audience :: Information Technology",
    "Topic :: Security",
    "Topic :: Software Development :: Testing",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
]
dependencies = [
    "typer[all]>=0.9.0",
    "httpx>=0.24.0",
    "prompt-toolkit>=3.0.0",
    "rich>=13.0.0",
]

[project.urls]
Homepage = "https://wafrunner.com"
Documentation = "https://docs.wafrunner.com"
Repository = "https://github.com/wafrunner/wafrunner-cli"
Issues = "https://github.com/wafrunner/wafrunner-cli/issues"
```

2. **Add build dependencies:**
```toml
[build-system]
requires = ["setuptools>=61.0", "wheel", "build"]
build-backend = "setuptools.build_meta"
```

3. **Create GitHub Actions workflow for automated releases:**
```yaml
# .github/workflows/release.yml
name: Release

on:
  release:
    types: [created]
  workflow_dispatch:
    inputs:
      version:
        description: 'Version to release'
        required: true

jobs:
  build-and-publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install build tools
        run: pip install build twine

      - name: Build package
        run: python -m build

      - name: Publish to TestPyPI (for testing)
        if: github.event.release.prerelease
        env:
          TWINE_USERNAME: __token__
          TWINE_PASSWORD: ${{ secrets.TESTPYPI_API_TOKEN }}
        run: twine upload --repository testpypi dist/*

      - name: Publish to PyPI
        if: github.event.release.prerelease == false
        env:
          TWINE_USERNAME: __token__
          TWINE_PASSWORD: ${{ secrets.PYPI_API_TOKEN }}
        run: twine upload dist/*
```

### Option 2: Private PyPI Server

**Use Case:** Internal/enterprise deployment

**Pros:**
- Control over distribution
- Private packages
- Custom authentication

**Cons:**
- Requires infrastructure setup
- More complex than public PyPI

**Tools:**
- `pypiserver` (simple)
- `devpi` (more features)
- AWS CodeArtifact
- Azure Artifacts

### Option 3: GitHub Releases + pip install from git

**Use Case:** Quick releases, not ready for PyPI

**Pros:**
- No PyPI account needed
- Works immediately
- Can use git tags for versioning

**Cons:**
- Requires git to install
- No automatic dependency resolution from PyPI
- Less discoverable

**Installation:**
```bash
pip install git+https://github.com/wafrunner/wafrunner-cli@v0.1.0
```

### Option 4: Standalone Executables (PyInstaller/cx_Freeze)

**Use Case:** Distribution without Python requirement

**Pros:**
- Single executable file
- No Python installation needed
- Cross-platform support

**Cons:**
- Larger file sizes
- More complex build process
- Platform-specific builds needed

## Recommended Approach for Release Candidate

**Phase 1: TestPyPI (Validation)**
1. Publish to TestPyPI first
2. Test installation: `pip install --index-url https://test.pypi.org/simple/ wafrunner-cli`
3. Validate all functionality works

**Phase 2: PyPI Release**
1. Publish to production PyPI
2. Users install with: `pip install wafrunner-cli`
3. Updates: `pip install --upgrade wafrunner-cli`

## Version Management Strategy

**Semantic Versioning:**
- `0.1.0rc1` - Release candidate 1
- `0.1.0rc2` - Release candidate 2
- `0.1.0` - First stable release
- `0.1.1` - Patch release
- `0.2.0` - Minor release
- `1.0.0` - Major release

**Automation Options:**
- Use `bump2version` or `semantic-version` for version management
- Auto-increment on releases via CI/CD
- Tag releases in git

## Additional Recommendations

### 1. Add Installation Instructions to README

```markdown
## Installation

### From PyPI (Recommended)
```bash
pip install wafrunner-cli
```

### From Source
```bash
git clone https://github.com/wafrunner/wafrunner-cli.git
cd wafrunner-cli
pip install -e .
```

### Development Installation
```bash
pip install -e ".[test]"
pre-commit install
```
```

### 2. Add Build Scripts

Create `scripts/build.sh`:
```bash
#!/bin/bash
set -e

# Clean previous builds
rm -rf dist/ build/ *.egg-info

# Build package
python -m build

# Check package
twine check dist/*
```

### 3. Add Release Checklist

- [ ] Update version in `pyproject.toml`
- [ ] Update CHANGELOG.md
- [ ] Run all tests: `make test`
- [ ] Run linting: `make lint`
- [ ] Build package: `python -m build`
- [ ] Test installation: `pip install dist/wafrunner_cli-*.whl`
- [ ] Create git tag: `git tag v0.1.0rc1`
- [ ] Push tag: `git push origin v0.1.0rc1`
- [ ] Create GitHub release
- [ ] Publish to PyPI/TestPyPI

### 4. Consider Adding:

- `CHANGELOG.md` - Track changes between versions
- `.github/workflows/ci.yml` - Continuous integration
- `.github/workflows/release.yml` - Automated releases
- `MANIFEST.in` - Include additional files in package
- Version management tool (bump2version, semantic-version)

## Quick Start: PyPI Deployment

1. **Install build tools:**
   ```bash
   pip install build twine
   ```

2. **Build package:**
   ```bash
   python -m build
   ```

3. **Check package:**
   ```bash
   twine check dist/*
   ```

4. **Test on TestPyPI:**
   ```bash
   twine upload --repository testpypi dist/*
   ```

5. **Install from TestPyPI:**
   ```bash
   pip install --index-url https://test.pypi.org/simple/ wafrunner-cli
   ```

6. **Publish to PyPI:**
   ```bash
   twine upload dist/*
   ```

## Conclusion

**For a release candidate, I recommend:**
1. ✅ **PyPI via TestPyPI first** - Validate the package works
2. ✅ **Then PyPI production** - For public distribution
3. ✅ **Automate with GitHub Actions** - For consistent releases
4. ✅ **Use semantic versioning** - For clear version management

The current `pyproject.toml` is already well-configured for PyPI deployment. You mainly need to:
- Enhance metadata (classifiers, URLs, etc.)
- Set up build/CI/CD pipeline
- Create release process documentation
- Test on TestPyPI before production

Would you like me to help implement any of these recommendations?
