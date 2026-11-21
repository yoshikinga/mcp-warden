import eslint from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  eslint.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      "eqeqeq": ["error", "always"],
      "no-eval": "error",
      "prefer-const": "error",
      "no-console": "error",
      "@typescript-eslint/consistent-type-imports": [
        "error",
        { prefer: "type-imports", fixStyle: "inline-type-imports" }
      ],
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }
      ],
      "@typescript-eslint/explicit-function-return-type": [
        "error",
        { allowExpressions: true, allowTypedFunctionExpressions: true }
      ]
    }
  },
  {
    files: ["tests/**/*.ts", "benchmarks/**/*.ts", "examples/**/*.ts"],
    rules: {
      "no-console": "off"
    }
  },
  {
    ignores: ["dist/**", "node_modules/**", "eslint.config.mjs"]
  }
);
