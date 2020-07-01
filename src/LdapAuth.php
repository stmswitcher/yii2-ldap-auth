<?php
declare(strict_types=1);

namespace stmswitcher\Yii2LdapAuth;

use stmswitcher\Yii2LdapAuth\Exception\Yii2LdapAuthException;
use yii\base\Component;

/**
 * Connector to LDAP server.
 *
 * @package stmswitcher\Yii2LdapAuth\Components
 * @author Denis Alexandrov <stm.switcher@gmail.com>
 * @date 30.06.2020
 */
class LdapAuth extends Component
{
    private const DEFAULT_TIMEOUT = 10;
    private const DEFAULT_CONNECT_TIMEOUT = 10;
    private const DEFAULT_PROTOCOL = 'ldaps://';
    private const DEFAULT_PORT = 636;
    private const DEFAULT_LDAP_VERSION = 3;
    private const DEFAULT_LDAP_OBJECT_CLASS = 'person';
    private const DEFAULT_UID_ATTRIBUTE = 'uid';

    /**
     * @var string LDAP base distinguished name.
     */
    public $baseDn;

    /**
     * @var bool If connector should follow referrals.
     */
    public $followReferrals = false;

    /**
     * @var string Protocol to use.
     */
    public $protocol = self::DEFAULT_PROTOCOL;

    /**
     * @var string LDAP server URL.
     */
    public $host;

    /**
     * @var int LDAP port to use.
     */
    public $port = self::DEFAULT_PORT;

    /**
     * @var string username of the search user that would look up entries.
     */
    public $searchUserName;

    /**
     * @var string password of the search user.
     */
    public $searchUserPassword;

    /**
     * @var string LDAP object class.
     */
    public $ldapObjectClass = self::DEFAULT_LDAP_OBJECT_CLASS;

    /**
     * @var string attribute to look up for.
     */
    public $loginAttribute = self::DEFAULT_UID_ATTRIBUTE;

    /**
     * @var int LDAP protocol version
     */
    public $ldapVersion = self::DEFAULT_LDAP_VERSION;

    /**
     * @var int Operation timeout.
     */
    public $timeout = self::DEFAULT_TIMEOUT;

    /**
     * @var int Connection timeout.
     */
    public $connectTimeout = self::DEFAULT_CONNECT_TIMEOUT;

    /**
     * @var resource|false
     */
    protected $connection;

    /**
     * Establish connection to LDAP server and bind search user.
     *
     * @throws Yii2LdapAuthException
     */
    protected function connect(): void
    {
        if (is_resource($this->connection)) {
            return;
        }

        $this->connection = ldap_connect($this->protocol . $this->host, $this->port);

        ldap_set_option($this->connection, LDAP_OPT_PROTOCOL_VERSION, $this->ldapVersion);
        ldap_set_option($this->connection, LDAP_OPT_REFERRALS, $this->followReferrals);

        ldap_set_option($this->connection, LDAP_OPT_NETWORK_TIMEOUT, $this->connectTimeout);
        ldap_set_option($this->connection, LDAP_OPT_TIMELIMIT, $this->timeout);

        if (!$this->connection) {
            throw new Yii2LdapAuthException(
                'Unable to connect to LDAP. Code '
                . ldap_errno($this->connection)
                . '. Message: '
                . ldap_error($this->connection)
            );
        }

        if (!@ldap_bind($this->connection, $this->searchUserName, $this->searchUserPassword)) {
            throw new Yii2LdapAuthException(
                'Unable to bind LDAP search user. Code '
                . ldap_errno($this->connection)
                . '. Message: '
                . ldap_error($this->connection)
            );
        }
    }

    /**
     * @return resource
     * @throws Yii2LdapAuthException
     */
    public function getConnection()
    {
        $this->connect();
        return $this->connection;
    }

    /**
     * @param string $uid
     *
     * @return array Data from LDAP or null
     * @throws Yii2LdapAuthException
     */
    public function searchUid(string $uid): ?array
    {
        $result = ldap_search(
            $this->getConnection(),
            $this->baseDn,
            '(&(objectClass=' . $this->ldapObjectClass . ')(' . $this->loginAttribute . '=' . $uid . '))'
        );

        $entries = ldap_get_entries($this->getConnection(), $result);

        return $entries[0] ?? null;
    }

    /**
     * @param string $dn
     * @param string $password
     * @param string|null $group
     *
     * @return bool
     * @throws Yii2LdapAuthException
     */
    public function authenticate(string $dn, string $password, ?string $group = null): bool
    {
        if (!@ldap_bind($this->getConnection(), $dn, $password)) {
            return false;
        }

        if (!$group) {
            return true;
        }

        return $this->isUserInAGroup($dn, $group);
    }

    /**
     * @param string $dn
     * @param string $group
     *
     * @return bool
     * @throws Yii2LdapAuthException
     */
    protected function isUserInAGroup(string $dn, string $group): bool
    {
        $result = ldap_search(
            $this->getConnection(),
            $this->baseDn,
            '(&(objectClass=groupOfUniqueNames)(uniqueMember=' . $dn . '))'
        );

        $entries = ldap_get_entries($this->getConnection(), $result);

        for ($i = $entries['count']; $i > 0; $i--) {
            $dn = $entries[$i - 1]['dn'];
            if (strrpos($dn, $group, -strlen($dn)) !== false) {
                return true;
            }
        }

        return false;
    }
}
