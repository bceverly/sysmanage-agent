# Installation Notes

## FreeBSD Specific Instructions

### Coverage Package
On FreeBSD, the coverage package needs to be installed from source to properly compile the C tracer extension and avoid warnings:

```bash
pip install coverage --no-binary coverage --force-reinstall
```

This ensures the C tracer is available and eliminates the "Couldn't import C tracer" warning during test runs.

### Alternative Approach
If you continue to see coverage warnings, they can be suppressed via the pytest.ini configuration file (already configured in this project).