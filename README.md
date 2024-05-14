_Note that this is very much not a finished package. Consider it a tech demo, or a small
proof of concept, and feel free to use it however you'd like, but I would not recommend
using it in production as-is._

# Installation

1. `pip install django-passkey-auth`
2. Add `passkeys` to your `INSTALLED_APPS` setting
3. Include `passkeys.urls` somewhere in your `urls.py` (`auth/passkey/` for example)
3. Migrate your database


## Integration with the Django admin

`django-passkey-auth` comes with some basic admin template overrides that make it
possible to register and authenticate with a passkey to the Django admin. To use these
customizations, add `passkeys.template_directory` to your `TEMPLATES["DIRS"]` list.

The next time you log into the admin, a "Register Passkey" link will be available in the
user links at the top. Once you have registered a passkey, you can use the "Passkey
Login" button available on the admin login form.


## Integration with your site

* Add `<script src="{% static 'passkeys/passkeys.js' %}" defer></script>` to your login
  page, and any page where you may want to allow users to register a passkey.
* Add a button to allow users to register a passkey:
    ```html
    <button onclick="registerPasskey('{% url "passkey-register" %}', '{% url "home" %}')">Register Passkey</button>
    ```
* Add a button to your login page to allow users to authenticate with a passkey:
    ```html
    <button onclick="authenticatePasskey('{% url "passkey-login" %}', '{% url "home" %}')">Passkey Login</button>
    ```

## Javascript functions

The `passkeys.js` script contains two functions:

### `async function registerPasskey(endpoint, redirect)`

### `async function authenticatePasskey(endpoint, redirect)`
