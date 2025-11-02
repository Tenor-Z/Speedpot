# Contributing to Speedpot

First off, thank you for considering contributing to Speedpot! It's people like you that make Speedpot such a great tool.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. Please report unacceptable behavior to the project maintainers.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the issue list as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

* **Use a clear and descriptive title**
* **Describe the exact steps which reproduce the problem** in as many details as possible
* **Provide specific examples to demonstrate the steps**
* **Describe the behavior you observed after following the steps**
* **Explain which behavior you expected to see instead and why**
* **Include screenshots and animated GIFs if possible**
* **Include your Python version and OS**

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

* **Use a clear and descriptive title**
* **Provide a step-by-step description of the suggested enhancement**
* **Provide specific examples to demonstrate the steps**
* **Describe the current behavior and expected behavior**
* **Explain why this enhancement would be useful**

### Pull Requests

* Fill in the required template
* Follow the Python styleguide
* Include appropriate test cases
* End all files with a newline
* Avoid platform-dependent code

## Development Setup

1. **Fork the repository**
   ```bash
   git clone https://github.com/Tenor-Z/speedpot.git
   cd speedpot
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install development dependencies**
   ```bash
   pip install -r requirements-dev.txt
   ```

4. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Styleguides

### Python Code Style

* Follow PEP 8
* Use meaningful variable names
* Add docstrings to functions
* Maximum line length: 100 characters
* Use type hints where possible

### Git Commit Messages

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference issues and pull requests liberally after the first line
* Example:
  ```
  Add SQL injection detection for union-based attacks
  
  Implements pattern matching for UNION SELECT queries.
  Closes #42
  ```

### Documentation

* Update README.md with any new features
* Add comments to complex code sections
* Update docstrings when modifying functions
* Include examples for new attack detection patterns

## Testing

Before submitting a pull request:

1. Test on Windows (primary platform)
2. Test with various network configurations
3. Test with both GUI and CLI operations
4. Verify no regressions with existing functionality

### Manual Testing Checklist

- [ ] Honeypot starts without errors
- [ ] Services bind to configured ports
- [ ] Attack patterns are detected correctly
- [ ] Blocking functionality works
- [ ] Logs are generated and cleaned up properly
- [ ] Database operations succeed
- [ ] GUI remains responsive during attacks

## Additional Notes

### Issue and Pull Request Labels

* `bug` - Something isn't working
* `enhancement` - New feature or request
* `documentation` - Improvements or additions to documentation
* `good first issue` - Good for newcomers
* `help wanted` - Extra attention is needed

## Recognition

Contributors will be recognized in:
* The README.md file
* GitHub contributors page
* Release notes

## Questions?

Feel free to open an issue or contact me.

Thank you for contributing to Speedpot!
