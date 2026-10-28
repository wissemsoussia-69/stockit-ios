# StockIT — Application iOS

Version iPhone/iPad de StockIT (SwiftUI). La logique métier est écrite une seule fois en
Kotlin Multiplatform dans le module `shared/` et compilée en framework iOS (`Shared.framework`).

## Architecture

```
shared/        Kotlin Multiplatform : base locale SQLDelight, StockItRepository (ex-MainController),
               Jira, Slack, webhook n8n, passerelles IA (Cimpress → Portkey → Gemini → Hugging Face),
               TicketMatcher, parsers facture / étiquette, session.
iosApp/        Application SwiftUI
  StockIT/App        point d'entrée, état global (splash → login → main)
  StockIT/Services   Auth0 (Vista SSO), caméra AVFoundation, Apple Vision (OCR + reconnaissance),
                     notifications, PDF, widget
  StockIT/Views      tous les écrans
  StockITWidget/     widget écran d'accueil
  project.yml        définition du projet (XcodeGen)
```

| Android (Java)                  | iOS                                         |
|---------------------------------|---------------------------------------------|
| Room                            | SQLDelight (shared)                         |
| OkHttp / Retrofit               | Ktor (shared, moteur NSURLSession)          |
| ML Kit OCR / labeling / barcode | Apple Vision / AVFoundation                 |
| CameraX                         | AVCaptureSession                            |
| Auth0 Android                   | Auth0.swift (Keychain)                      |
| iText PDF                       | UIGraphicsPDFRenderer                       |
| MPAndroidChart                  | Swift Charts                                |
| AppWidget                       | WidgetKit                                   |

## Prérequis

- Mac avec **Xcode 15 ou plus récent** (App Store), puis `sudo xcode-select -s /Applications/Xcode.app`
- JDK 17+ : `brew install openjdk@21`
- XcodeGen : `brew install xcodegen`

## Configuration des clés

Copier `.env.sh.example` en `.env.sh` à la racine et le remplir. Les valeurs sont intégrées
au framework partagé **au moment du build** (fichier généré dans `shared/build/`, jamais commité).
Le backend des réclamations se configure avec `STOCKIT_API_BASE_URL` (ex. `http://localhost/api/`).

Auth0 / Okta (Vista SSO) : tenant `<AUTH0_DOMAIN>`, connexion `vista-okta` (Info.plist).
L'app utilise les URL déjà autorisées dans l'application Auth0 :

```
callback : com.example.stockit://<AUTH0_DOMAIN>/android/com.example.stockit/callback
logout   : stockit://logout
```

Pour utiliser l'URL iOS standard, un administrateur Auth0 doit ajouter
`com.example.stockit://<AUTH0_DOMAIN>/ios/com.example.stockit/callback` aux *Allowed Callback URLs*,
puis on remplace `Auth0CallbackURL` dans Info.plist.

## Lancer l'app

```bash
cd iosApp
xcodegen generate        # (re)génère StockIT.xcodeproj
open StockIT.xcodeproj
```

Dans Xcode :
1. Cible **StockIT** et cible **StockITWidget** → *Signing & Capabilities* → choisir votre **Team**
   (ajuster les Bundle Identifier si `com.example.stockit` est déjà pris, ainsi que l'App Group
   `group.com.example.stockit`).
2. Choisir un simulateur iPhone ou un iPhone branché → **Run** (⌘R).
   La phase « Compile Kotlin (shared) » construit automatiquement le framework partagé
   (le premier build prend quelques minutes).

En mode Debug uniquement, l'écran de connexion propose un accès de secours local. Aucun compte n'existe
par défaut : les tests UI créent leur propre compte (mot de passe aléatoire à chaque exécution) via les
variables `STOCKIT_UITEST_USER` / `STOCKIT_UITEST_PASSWORD` / `STOCKIT_UITEST_ROLE`. En Release, seule la
connexion Vista SSO est possible. Voir [SECURITY.md](SECURITY.md).

## Tests

```bash
./gradlew :shared:testAndroidHostTest           # tests de la logique partagée (JVM)
./gradlew :shared:iosSimulatorArm64Test         # mêmes tests sur iOS (nécessite Xcode)
STOCKIT_LIVE=1 ./gradlew :shared:testAndroidHostTest               # + lecture réelle Jira Assets
STOCKIT_LIVE=1 STOCKIT_LIVE_WRITE=1 ./gradlew :shared:testAndroidHostTest  # + écritures (schéma de test !)
```

Les dépendances Gradle sont vérifiées (`gradle/verification-metadata.xml`). Après un changement de
version : `./gradlew --write-verification-metadata sha256 :shared:testAndroidHostTest :shared:iosSimulatorArm64Test
:shared:linkDebugFrameworkIosSimulatorArm64 :shared:linkReleaseFrameworkIosArm64 :shared:linkDebugFrameworkIosArm64`
puis relire le diff.

## Différences avec Android

- La caméra ne fonctionne pas sur le simulateur : tester les scans sur un iPhone réel.
- Le scan d'équipement passe d'abord par les IA distantes ; hors ligne, la classification
  Apple Vision remplace ML Kit.
- Les notifications push Firebase ne sont pas portées. Les notifications locales fonctionnent ;
  les push serveur nécessitent un compte Apple Developer (clé APNs) et le SDK Firebase iOS.
- Le brouillon de commande IA (Prévision des besoins / fiche produit) crée un bon de commande
  « En attente » dans StockIT et prévient l'équipe sur Slack.
