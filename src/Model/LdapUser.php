<?php
declare(strict_types=1);

namespace stmswitcher\Yii2LdapAuth\Model;

use stmswitcher\Yii2LdapAuth\Exception\Yii2LdapAuthException;
use Yii;
use yii\base\BaseObject;
use yii\web\IdentityInterface;

/**
 * LDAP user model.
 *
 * @package stmswitcher\Yii2LdapAuth\Model
 * @author Denis Alexandrov <stm.switcher@gmail.com>
 * @date 30.06.2020
 */
class LdapUser extends BaseObject implements IdentityInterface
{
    /**
     * @var string LDAP UID of a user.
     */
    private $id;

    /**
     * @var string Display name of a user.
     */
    private $username;

    /**
     * @var string Email of a user.
     */
    private $email;

    /**
     * @var string distinguished name of the user within LDAP.
     */
    private $dn;

    /**
     * LdapUser constructor.
     *
     * @param array $config
     */
    public function __construct($config = [])
    {
        parent::__construct($config);
    }

    /**
     * @return string
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * @param string $id
     */
    public function setId(string $id): void
    {
        $this->id = $id;
    }

    /**
     * @return string
     */
    public function getUsername(): string
    {
        return $this->username;
    }

    /**
     * @param string $username
     */
    public function setUsername(string $username): void
    {
        $this->username = $username;
    }

    /**
     * @return string
     */
    public function getEmail(): string
    {
        return $this->email;
    }

    /**
     * @param string $email
     */
    public function setEmail(string $email): void
    {
        $this->email = $email;
    }

    /**
     * @return string
     */
    public function getDn(): string
    {
        return $this->dn;
    }

    /**
     * @param string $dn
     */
    public function setDn(string $dn): void
    {
        $this->dn = $dn;
    }

    /**
     * @param int|string $uid
     *
     * @return IdentityInterface|null
     */
    public static function findIdentity($uid)
    {
        $user = Yii::$app->ldapAuth->searchUid($uid);

        if (!$user) {
            return null;
        }

        return new static([
            'Id' => $user['uid'][0],
            'Username' => $user['displayname'][0],
            'Email' => $user['mail'][0],
            'Dn' => $user['dn'],
        ]);
    }

    /**
     * {@inheritDoc}
     * @throws Yii2LdapAuthException
     */
    public static function findIdentityByAccessToken($token, $type = null)
    {
        throw new Yii2LdapAuthException('Access token are not supported');
    }

    /**
     * {@inheritDoc}
     */
    public function getAuthKey()
    {
        return hash('sha256', $this->id);
    }

    /**
     * {@inheritDoc}
     */
    public function validateAuthKey($authKey)
    {
        return $authKey === hash('sha256', $this->id);
    }
}
