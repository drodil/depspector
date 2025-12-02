// @ts-check

import eslint from "@eslint/js";
import tseslint from "@typescript-eslint/eslint-plugin";
import tsparser from "@typescript-eslint/parser";

export default [
  {
    ignores: [
      "dist/**",
      "coverage/**",
      "node_modules/**",
      "tests/fixtures/**",
      "*.config.js",
      ".cache/**",
      "index.js",
      "index.d.ts",
    ],
  },
  {
    files: ["**/*.ts", "**/*.tsx"],
    languageOptions: {
      parser: tsparser,
      parserOptions: {
        ecmaVersion: "latest",
        sourceType: "module",
      },
      globals: {
        // Node.js globals
        process: "readonly",
        __dirname: "readonly",
        __filename: "readonly",
        require: "readonly",
        module: "readonly",
        exports: "writable",
        console: "readonly",
        Buffer: "readonly",
        global: "readonly",
      },
    },
    plugins: {
      "@typescript-eslint": tseslint,
    },
    rules: {
      ...eslint.configs.recommended.rules,
      ...tseslint.configs.recommended.rules,

      // TypeScript-specific rules
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
        },
      ],
      "@typescript-eslint/explicit-function-return-type": "off",
      "@typescript-eslint/no-non-null-assertion": "warn",
      "@typescript-eslint/no-require-imports": "off", // Allow require() for now
      "@typescript-eslint/no-var-requires": "off", // Allow var requires

      // General code quality
      "no-console": "off", // CLI tool needs console
      "prefer-const": "error",
      "no-var": "error",
      eqeqeq: ["warn", "always"], // Changed to warn
      curly: "off", // Disabled for now

      // Best practices
      "no-throw-literal": "warn", // Changed to warn
      "no-unused-expressions": "off", // Disabled for now
      "prefer-promise-reject-errors": "warn", // Changed to warn
    },
  },
  {
    files: ["**/*.test.ts", "**/*.spec.ts"],
    rules: {
      "@typescript-eslint/no-explicit-any": "off",
    },
  },
];
