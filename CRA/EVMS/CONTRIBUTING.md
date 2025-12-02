<!-- EVMS (c) Shane D. Shook, PhD, 2025 All Rights Reserved -->
# Contributing to EVMS

Thank you for your interest in contributing to the Exposure and Vulnerability Management System (EVMS). This document provides guidelines and information for contributors.

## Code of Conduct

This project adheres to a Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## How to Contribute

### Reporting Issues

Before creating an issue, please:

1. **Search existing issues** to avoid duplicates
2. **Use the issue template** provided
3. **Provide detailed information** including:
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details
   - Relevant logs or screenshots

### Development Process

1. **Fork the repository** and create your branch from `main`
2. **Set up your development environment** following the setup guide
3. **Make your changes** following our coding standards
4. **Add tests** for any new functionality
5. **Ensure all tests pass** and coverage requirements are met
6. **Update documentation** as needed
7. **Submit a pull request** with a clear description

### Coding Standards

#### JavaScript/Node.js
- Follow ESLint configuration provided
- Use Prettier for code formatting
- Write meaningful variable and function names
- Add JSDoc comments for public APIs
- Maintain test coverage above 80%

#### Python
- Follow PEP 8 style guide
- Use Black for code formatting
- Use type hints for function signatures
- Write docstrings for all public functions
- Maintain test coverage above 80%

#### Security Guidelines
- Never commit secrets or credentials
- Validate all user inputs
- Use parameterized queries for database operations
- Follow OWASP security guidelines
- Implement proper error handling

### Testing

#### Unit Tests
- Write tests for all new functionality
- Use descriptive test names
- Follow AAA pattern (Arrange, Act, Assert)
- Mock external dependencies

#### Integration Tests
- Test component interactions
- Use test databases and services
- Clean up test data after each test

#### Security Tests
- Include security-focused test cases
- Test input validation and sanitization
- Verify authentication and authorization

### Documentation

- Update README.md for significant changes
- Add API documentation for new endpoints
- Update architecture diagrams if needed
- Include examples and usage instructions

### Pull Request Process

1. **Create a descriptive title** summarizing the change
2. **Fill out the PR template** completely
3. **Link related issues** using keywords (fixes #123)
4. **Request review** from appropriate team members
5. **Address feedback** promptly and professionally
6. **Ensure CI passes** before requesting final review

### Commit Message Format

Use conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test additions or modifications
- `chore`: Maintenance tasks

Examples:
```
feat(graphrl): add risk scoring algorithm
fix(agents): resolve memory leak in scanner pool
docs(api): update authentication endpoints
```

### Development Environment Setup

1. **Prerequisites**:
   - Node.js 18+
   - Python 3.9+
   - Docker and Docker Compose
   - Git

2. **Installation**:
   ```bash
   git clone https://github.com/sdshook/Tools.git
   cd Tools/CRA/EVMS
   npm install
   pip install -r requirements.txt
   ```

3. **Configuration**:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Start development services**:
   ```bash
   docker-compose up -d
   npm run dev
   ```

### Release Process

1. **Version Bumping**: Follow semantic versioning
2. **Changelog**: Update CHANGELOG.md with changes
3. **Testing**: Ensure all tests pass in CI/CD
4. **Documentation**: Update version-specific docs
5. **Tagging**: Create and push version tags
6. **Deployment**: Follow deployment procedures

### Getting Help

- **Documentation**: Check existing docs first
- **Issues**: Search existing issues for similar problems
- **Discussions**: Use GitHub Discussions for questions
- **Contact**: Reach out to maintainers for urgent matters

### Recognition

Contributors will be recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project documentation

Thank you for contributing to EVMS!