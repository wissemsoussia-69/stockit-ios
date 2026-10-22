# StockIT — iOS

Application iOS (SwiftUI) de gestion du stock informatique : scan d'équipements par IA,
réception de colis, sorties sur tickets Jira, inventaire synchronisé avec Jira Assets.

- `iosApp/` : application SwiftUI, widget et tests UI
- `shared/` : logique métier en Kotlin Multiplatform, compilée en `Shared.framework`
  (nécessaire à la compilation de l'app iOS)

## Prérequis

- macOS avec **Xcode 15+**
- **JDK 17+** et **XcodeGen** : `brew install openjdk@21 xcodegen`
- Un compte Apple (équipe de signature) pour installer sur un iPhone

## Compiler

```bash
cp .env.sh.example .env.sh        # puis renseigner vos valeurs
cd iosApp
xcodegen generate
open StockIT.xcodeproj
```

Dans Xcode, choisissez votre équipe dans *Signing & Capabilities* (cibles StockIT et StockITWidget),
puis lancez avec ⌘R. La phase « Compile Kotlin (shared) » compile automatiquement le module partagé.

Tests :

```bash
./gradlew :shared:testAndroidHostTest
cd iosApp && xcodebuild test -scheme StockIT -destination 'platform=iOS Simulator,name=iPhone 17'
```

Plus de détails : [README_IOS.md](README_IOS.md).

## Secrets

**Les secrets (clés API, tokens, adresses des webhooks, configuration Auth0) se trouvent uniquement
dans `.env.sh`, en local. Ce fichier est ignoré par git et n'est jamais versionné.**
`.env.sh.example` ne contient que les noms des clés, avec des valeurs vides.
