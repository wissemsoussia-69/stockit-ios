import Foundation
import Auth0
import Shared

/// Vista SSO via Auth0 Universal Login (portage de util/Auth0Manager.java).
/// Les credentials sont stockés dans le Keychain (CredentialsManager).
final class AuthService {
    static let shared = AuthService()
    /// Pas de `offline_access` : aucune session ne survit à la fermeture de l'app, un refresh token
    /// (valable longtemps, réutilisable s'il est volé) n'a donc aucune utilité.
    private let scope = "openid profile email"

    private lazy var credentials: CredentialsManager? = {
        guard isConfigured else { return nil }
        let api = Auth0.authentication(clientId: AppConfig.auth0ClientId, domain: AppConfig.auth0Domain)
        return CredentialsManager(authentication: api)
    }()

    var isConfigured: Bool {
        let d = AppConfig.auth0Domain, c = AppConfig.auth0ClientId
        return !d.isEmpty && !c.isEmpty && !d.contains("REPLACE") && !c.contains("REPLACE")
    }

    struct Profile { let subject: String; let username: String; let email: String?; let role: String }

    func signIn() async throws -> Profile {
        guard isConfigured, let cm = credentials else {
            throw NSError(domain: "StockIT", code: 1, userInfo: [NSLocalizedDescriptionKey:
                L("Auth0 non configuré : renseignez Auth0Domain et Auth0ClientId dans Info.plist.")])
        }
        // Session éphémère : aucun cookie Okta n'est conservé → identifiants redemandés à chaque fois.
        // Auth0.swift vérifie la signature, l'émetteur, l'audience, le nonce et l'expiration de l'ID token.
        var wa = Auth0.webAuth(clientId: AppConfig.auth0ClientId, domain: AppConfig.auth0Domain)
            .scope(scope)
            .useEphemeralSession()
        let audience = StockItConfig.shared.auth0Audience
        if !audience.isEmpty { wa = wa.audience(audience) }
        if !AppConfig.auth0Connection.isEmpty { wa = wa.connection(AppConfig.auth0Connection) }
        if let cb = AppConfig.auth0CallbackURL { wa = wa.redirectURL(cb) }
        let c = try await wa.start()

        let claims = Self.decodeJWT(c.idToken)
        var flat: [String: String] = [:]
        for (k, v) in claims {
            if let arr = v as? [Any] { flat[k] = arr.map { "\($0)" }.joined(separator: ",") }
            else { flat[k] = "\(v)" }
        }
        // Défense en profondeur : les claims utilisés pour l'identité et le rôle sont re-contrôlés ici.
        if let problem = IdTokenValidator.shared.validate(claims: flat, domain: AppConfig.auth0Domain,
                                                           clientId: AppConfig.auth0ClientId,
                                                           nowSec: Int64(Date().timeIntervalSince1970)) {
            throw NSError(domain: "StockIT", code: 2, userInfo: [NSLocalizedDescriptionKey:
                L("Jeton d'identité refusé (%@)", problem)])
        }
        _ = cm.store(credentials: c)
        StockIt.shared.setAccessToken(token: c.accessToken)

        let subject = flat["sub"] ?? ""
        let email = claims["email"] as? String
        let username = [claims["nickname"] as? String, claims["name"] as? String, email]
            .compactMap { $0 }.first(where: { !$0.isEmpty }) ?? "vista.user"
        let role = RoleResolver.shared.resolve(claims: flat, defaultRole: StockItConfig.shared.ssoDefaultRole)
        StockIt.shared.session.saveSsoSession(username: username, email: email, role: role)
        return Profile(subject: subject, username: username, email: email, role: role)
    }

    /// Efface les tokens du Keychain sans ouvrir de navigateur (utilisable en arrière-plan).
    func clearLocalCredentials() {
        StockIt.shared.setAccessToken(token: nil)
        _ = credentials?.clear()
    }

    func signOut() async {
        StockIt.shared.setAccessToken(token: nil)
        guard isConfigured, let cm = credentials else { return }
        // Révocation côté Auth0 si un refresh token existe (anciennes sessions), puis purge du Keychain.
        try? await cm.revoke()
        _ = cm.clear()
    }

    private static func decodeJWT(_ jwt: String) -> [String: Any] {
        let parts = jwt.split(separator: ".")
        guard parts.count > 1 else { return [:] }
        var b64 = String(parts[1]).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b64.count % 4 != 0 { b64 += "=" }
        guard let data = Data(base64Encoded: b64),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [:] }
        return obj
    }
}
