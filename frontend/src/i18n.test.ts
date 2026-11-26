import { expect, it } from "vitest";
import { pickLang, translateText } from "./i18n";

it("detecta español, inglés y cae a inglés para otros idiomas", () => {
  expect(pickLang({ languages: ["es-CR", "en-US"] })).toBe("es");
  expect(pickLang({ languages: ["en-GB"] })).toBe("en");
  expect(pickLang({ languages: ["fr-FR"] })).toBe("en");
  expect(pickLang({ languages: ["de-DE", "es-ES"] })).toBe("en");
});

it("la URL y la preferencia guardada mandan sobre el navegador", () => {
  expect(pickLang({ search: "?lang=es", stored: "en", languages: ["en-US"] })).toBe("es");
  expect(pickLang({ search: "?lang=en", stored: "es", languages: ["es-ES"] })).toBe("en");
  expect(pickLang({ stored: "en", languages: ["es-ES"] })).toBe("en");
});

it("traduce cadenas exactas y patrones dinámicos", () => {
  expect(translateText("Resumen", "en")).toBe("Summary");
  expect(translateText("Cerrar sesión", "en")).toBe("Sign out");
  expect(translateText("Página 3 de 8", "en")).toBe("Page 3 of 8");
  expect(translateText("Investigación local / Incidencias", "en")).toBe(
    "Local investigation / Incidents",
  );
  expect(translateText("Resumen", "es")).toBe("Resumen");
  expect(translateText("texto sin traducción", "en")).toBe("texto sin traducción");
});
