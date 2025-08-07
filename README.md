_Note that this is very much not a finished package. Consider it a tech demo, or a small proof of concept, and feel free to use it however you'd like, but I would not recommend using it in production as-is._

# Installation

1. `pip install django-passkey-auth`
2. Add `passkeys` to your `INSTALLED_APPS` setting
3. Include `passkeys.urls` somewhere in your `urls.py` (`auth/passkey/` for example)
4. Migrate your database


## Integration with the Django admin

`django-passkey-auth` comes with some basic admin template overrides that make it possible to register and authenticate with a passkey to the Django admin. To use these customizations, add `passkeys.template_directory` to your `TEMPLATES["DIRS"]` list.

The next time you log into the admin, a "Register Passkey" link will be available in the user links at the top. Once you have registered a passkey, you can use the "Passkey Login" button available on the admin login form.


## Integration with your site

* Add `<script src="{% static 'passkeys/passkeys.js' %}"></script>` to your login page, and any page where you may want to allow users to register or use a passkey.
* Instead of passing `endpoint` and `redirect` to each method (which you can do via an options object, or using `data-` attributes of elements), you can initialize the `Passkeys` object with a default endpoint and redirect lcoation as follows:
    ```javascript
    Passkeys.init({
      endpoint: "{% url 'passkey-info' %}",
      redirect: "{% url 'home' %}",
    });
    ```
* Add a button to allow authenticated users to register a passkey:
    ```html
    <button onclick="Passkeys.register()">Register Passkey</button>
    ```
* Add a button to your login page to allow users to authenticate with a passkey:
    ```html
    <button data-redirect="{{ redir }}" onclick="Passkeys.authenticate()">Passkey Login</button>
    ```
* Add an autocomplete to your username field and call `autofill`:
    ```html
    <input type="text" name="username" autocomplete="username webauthn" autofocus />
    <script>
      Passkeys.autofill({
        redirect: '{{ redir }}',
      });
    </script>
    ```
