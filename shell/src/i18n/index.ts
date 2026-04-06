// SPDX-License-Identifier: MIT
// Delphi OS — i18next initialization

import i18n from "i18next";
import { initReactI18next } from "react-i18next";

import en from "./en.ts";

i18n.use(initReactI18next).init({
  resources: { en },
  lng: "en",
  fallbackLng: "en",
  initImmediate: false, // synchronous init — resources are bundled, no async needed
  interpolation: {
    escapeValue: false, // React already escapes
  },
});

export default i18n;
