# Contributing to Postmancer

Thank you for considering contributing to Postmancer! This document outlines the process for contributing to the project.

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/username/postmancer.git
   cd postmancer
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Build the project:
   ```bash
   npm run build
   ```

4. Run the server:
   ```bash
   npm start
   ```

## Making Changes

1. Create a new branch for your feature or fix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes and ensure tests pass:
   ```bash
   npm run lint
   npm test
   ```

3. Commit your changes with a descriptive message:
   ```bash
   git commit -m "Add feature: description of your changes"
   ```

4. Push your branch:
   ```bash
   git push origin feature/your-feature-name
   ```

5. Open a pull request against the main branch.

## Code Style

- Follow the existing code style
- Use meaningful variable and function names
- Add comments for complex logic
- Write tests for new features

## Reporting Issues

If you find a bug or have a feature request, please create an issue on GitHub with:

- Clear title and description
- Steps to reproduce (for bugs)
- Expected and actual behavior (for bugs)
- Any relevant screenshots or logs

## License

By contributing to Postmancer, you agree that your contributions will be licensed under the project's MIT License.