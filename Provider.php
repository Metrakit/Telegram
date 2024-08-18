<?php

namespace SocialiteProviders\Telegram;

use Illuminate\Support\Facades\Validator;
use InvalidArgumentException;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;

class Provider extends AbstractProvider
{
    public const IDENTIFIER = 'TELEGRAM';

    /**
     * {@inheritdoc}
     */
    public static function additionalConfigKeys()
    {
        return ['bot'];
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state = null)
    {
        return 'https://oauth.telegram.org/auth';
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
        return null;
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        return null;
    }

    public function getButton()
    {
        $botname = $this->getConfig('bot');
        $callbackUrl = $this->redirectUrl;

        return sprintf(
            '<script async src="https://telegram.org/js/telegram-widget.js" data-telegram-login="%s" data-size="large" data-userpic="false" data-auth-url="%s" data-request-access="write"></script>',
            $botname,
            $callbackUrl
        );
    }

    /**
     * Return the login script when using custom button.
     *
     * @return string
     */
    public function getScript()
    {
        $authUrl = $this->getAuthUrl();
        $botId = explode(':', $this->clientSecret)[0];
        $redirectUrl = $this->redirectUrl;

        return <<<EOD
<script>
    var _TWidgetLogin = {
        init: function(authUrl, bot_id, params, lang, redirectUrl) {
            _TWidgetLogin.authUrl = authUrl;
            _TWidgetLogin.botId = parseInt(bot_id);
            _TWidgetLogin.params = params;
            _TWidgetLogin.lang = lang;
            _TWidgetLogin.redirectUrl = redirectUrl;
            var params_encoded = '', params_arr = [];
            for (var k in params) {
                params_arr.push(encodeURIComponent(k) + '=' + encodeURIComponent(params[k]));
            }
            _TWidgetLogin.paramsEncoded = params_arr.join('&');
        },
        auth: function() {
            var width = 550;
            var height = 450;
            var left = Math.max(0, (screen.width - width) / 2) + (screen.availLeft | 0),
                top = Math.max(0, (screen.height - height) / 2) + (screen.availTop | 0);
            function checkClose() {
                if (!_TWidgetLogin.activePopup || _TWidgetLogin.activePopup.closed) {
                    return _TWidgetLogin.onClose();
                }
                setTimeout(checkClose, 100);
            }
            _TWidgetLogin.activePopup = window.open(_TWidgetLogin.authUrl + '?bot_id=' + _TWidgetLogin.botId + (_TWidgetLogin.lang ? '&lang=' + _TWidgetLogin.lang : '') + (_TWidgetLogin.paramsEncoded ? '&' + _TWidgetLogin.paramsEncoded : ''), 'telegram_oauth', 'width=' + width + ',height=' + height + ',left=' + left + ',top=' + top + ',status=0,location=0,menubar=0,toolbar=0');
            _TWidgetLogin.authFinished = false;
            if (_TWidgetLogin.activePopup) {
                _TWidgetLogin.activePopup.focus();
                checkClose();
            }
        },
        getAuth: function() {
            var xhr = navigator.appName == "Microsoft Internet Explorer"
                        ? new ActiveXObject("Microsoft.XMLHTTP")
                        : new XMLHttpRequest;
            xhr.open('POST', _TWidgetLogin.authUrl + '/get?bot_id=' + _TWidgetLogin.botId + (_TWidgetLogin.lang ? '&lang=' + encodeURIComponent(_TWidgetLogin.lang) : ''));
            xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8');
            xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
            xhr.onreadystatechange = function() {
                if (
                       xhr.readyState == XMLHttpRequest.DONE
                    && typeof xhr.responseBody == 'undefined'
                    && xhr.responseText
                ) {
                    _TWidgetLogin.onAuth(JSON.parse(xhr.responseText));
                }
            };
            xhr.onerror = function() {
                throw 'TG: Invalid response';
            };
            xhr.withCredentials = true;
            xhr.send('bot_id=' + encodeURIComponent(_TWidgetLogin.botId));
        },
        onAuth: function (response) {
            var data = {},
                urlQuery = [];

            if (response.user) {
                data = response.user;
            } else if (response.error) {
                data.error = response.error;
            } else {
                data = response;
                data.error = 'Unknown response';
            }

            Object.keys(data).forEach(function (key) {
                urlQuery.push(encodeURIComponent(key) + '=' + encodeURIComponent(data[key]));
            });

            location.href = _TWidgetLogin.redirectUrl + '?' + urlQuery.join('&');
        },
        onClose: function() {
            _TWidgetLogin.getAuth();
        }
    };
    window._TWidgetLogin = _TWidgetLogin;

    _TWidgetLogin.init(
        '$authUrl',
        '$botId',
        {"origin":location.href,"embed":1,"request_access":"write"},
        "en",
        '$redirectUrl'
    );
</script>
EOD;
    }

    /**
     * {@inheritdoc}
     */
    public function redirect()
    {
        return '<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8" />

        <title>Login using Telegram</title>
    </head>
    <body>
        '.$this->getButton().'
    </body>
</html>';
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        $name = trim(sprintf('%s %s', $user['first_name'] ?? '', $user['last_name'] ?? ''));

        return (new User())->setRaw($user)->map([
            'id'        => $user['id'],
            'nickname'  => $user['username'] ?? $user['first_name'],
            'name'      => ! empty($name) ? $name : null,
            'avatar'    => $user['photo_url'] ?? null,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function user()
    {
        $validator = Validator::make($this->request->all(), [
            'id'        => 'required|numeric',
            'auth_date' => 'required|date_format:U|before:1 day',
            'hash'      => 'required|size:64',
        ]);

        throw_if($validator->fails(), InvalidArgumentException::class);

        $dataToHash = collect($this->request->except('hash'))
            ->transform(fn ($val, $key) => "$key=$val")
            ->sort()
            ->join("\n");

        $hash_key = hash('sha256', $this->clientSecret, true);
        $hash_hmac = hash_hmac('sha256', $dataToHash, $hash_key);

        throw_if(
            $this->request->hash !== $hash_hmac,
            InvalidArgumentException::class
        );

        return $this->mapUserToObject($this->request->except(['auth_date', 'hash']));
    }
}
