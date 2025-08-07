var Passkeys = (function () {
    var defaults = {
        endpoint: "/auth/passkey/",
        redirect: "/",
    };

    async function fetchJSON(url, options) {
        const response = await fetch(url, options);
        return await response.json();
    }

    async function signalAccepted(info) {
        // Seems to be bugged at the moment...
        if (false && PublicKeyCredential.signalAllAcceptedCredentials) {
            await PublicKeyCredential.signalAllAcceptedCredentials({
                rpId: info.rpId,
                userId: info.userId,
                allAcceptedCredentialIds: info.credentials,
            });
        }
    }

    async function signalDetails(info) {
        if (PublicKeyCredential.signalCurrentUserDetails) {
            await PublicKeyCredential.signalCurrentUserDetails({
                rpId: info.rpId,
                userId: info.userId,
                name: info.userName,
                displayName: info.userDisplay,
            });
        }
    }

    // Public interface
    return {
        init: function (options) {
            if (options) {
                if (options.endpoint) defaults.endpoint = options.endpoint;
                if (options.redirect) defaults.redirect = options.redirect;
            }
        },

        register: async function (options = {}) {
            const opts = Object.assign(
                {},
                defaults,
                { endpoint: defaults.endpoint + "register/" },
                event && event.target ? event.target.dataset : {},
                options,
            );

            // Fetch the registration options and create the credential locally.
            const createOpts = await fetchJSON(opts.endpoint);
            const creds = await navigator.credentials.create({
                publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(createOpts),
            });

            const registerData = await fetchJSON(opts.endpoint, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(creds),
            });

            if (registerData.success) {
                await signalAccepted(registerData);
                if (opts.redirect) window.location = opts.redirect;
            }

            return false;
        },

        authenticate: async function (options = {}) {
            const opts = Object.assign(
                {},
                defaults,
                { endpoint: defaults.endpoint + "login/" },
                event && event.target ? event.target.dataset : {},
                options,
            );

            // Fetch the authentication challenge and find the local credential.
            const authOpts = await fetchJSON(opts.endpoint);
            const creds = await navigator.credentials.get({
                publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(authOpts),
                mediation: opts.mediation || "optional",
            });

            const responseData = await fetchJSON(opts.endpoint, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(creds),
            });

            if (responseData.success) {
                await signalAccepted(responseData);
                if (opts.redirect) window.location = opts.redirect;
            } else if (PublicKeyCredential.signalUnknownCredential) {
                await PublicKeyCredential.signalUnknownCredential({
                    rpId: authOpts.rpId,
                    credentialId: creds.id,
                });
            }

            return false;
        },

        autofill: async function (options = {}) {
            if (
                window.PublicKeyCredential &&
                PublicKeyCredential.isConditionalMediationAvailable
            ) {
                const cma = await PublicKeyCredential.isConditionalMediationAvailable();
                if (cma) {
                    const newOpts = Object.assign(
                        {},
                        { mediation: "conditional" },
                        options,
                    );
                    await this.authenticate(newOpts);
                }
            }
        },

        update: async function (options = {}) {
            const opts = Object.assign(
                {},
                defaults,
                event && event.target ? event.target.dataset : {},
                options,
            );

            // Fetch the authentication challenge and find the local credential.
            const info = await fetchJSON(opts.endpoint);
            if (info.userId) {
                // Specify to the browser which credentials the server accepts.
                await signalAccepted(info);
                // Specify the current user name/display to the browser.
                await signalDetails(info);
            }
        },
    };
})();
