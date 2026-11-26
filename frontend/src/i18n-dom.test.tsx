// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { LangProvider } from "./i18n";

function Demo() {
  return (
    <main>
      <h1>Resumen</h1>
      <p title="Cerrar sesión">Página 2 de 4</p>
      <code>Resumen</code>
    </main>
  );
}

afterEach(() => {
  localStorage.clear();
  history.replaceState(null, "", "/");
});

it("traduce el DOM completo y respeta atributos, sin tocar bloques de código", async () => {
  history.replaceState(null, "", "/?lang=en");
  render(
    <LangProvider>
      <Demo />
    </LangProvider>,
  );
  await waitFor(() => expect(screen.getByText("Summary")).toBeInTheDocument());
  expect(screen.getByText("Page 2 of 4")).toBeInTheDocument();
  expect(screen.getByTitle("Sign out")).toBeInTheDocument();
  expect(screen.getByText("Resumen", { selector: "code" })).toBeInTheDocument();
});
