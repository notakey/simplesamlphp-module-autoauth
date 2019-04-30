AutoAuth module
================

Allows to automatically select authentication source by specifying source IP address range
or matching user agents. Attempt is to improve AD FS intranet / extranet definition and avoid
showing HDR every time user authenticates, as errors in HRD selection can be hard to overcome
for users.

`autoauth:AutoAuth`
: Authenticate the user against a list of authentication sources.


`autoauth:AutoAuth`
---------------------

To create a autoauth authentication source, open
`config/authsources.php` in a text editor, and add an entry for the
authentication source:

    'example-auto' => array(
        'autoauth:AutoAuth',

        /*
         * The available authentication sources.
         * They must be defined in this authsources.php file.
         */
        'sources' => array(
            'example-saml' => array(

            ),
            'example-admin' => array(
                'subnets' => array('127.0.0.0/24', '10.0.1.0/24'),
            ),
            'example-boo' => array(
                'subnets' => array('192.168.0.0/16'),
            ),
        ),
        'default' => 'example-saml'
    ),

    'example-saml' => array(
        'saml:SP',
        'entityId' => 'my-entity-id',
        'idp' => 'my-idp',
    ),

    'example-admin' => array(
        'core:AdminPassword',
    ),

    'example-boo' => array(
        'core:AdminPassword',
    ),

Notakey Authentication appliance
---------------------

If running in NAA environment configure using cli:

    # Configure module authentication sources
    # autoselect can be any name for this virtual auth source
    ntk cfg set :sso.auth.autoselect '{
            "module": "autoauth:AutoAuth",
            "sources": {
                "adfs-wia": {
                    "subnets": ["172.17.0.0/24", "192.168.2.0/24"]
                },
                "notakey": {
                    "subnets": ["20.0.0.0/24", "202.168.2.0/24"]
                }
            },
            "default": "notakey",
            "ipsource": "HTTP_X_REAL_IP"
        }' --json-input

    # Enable module
    ntk cfg set :sso.modules '[..., "autoauth"]' --json-input

    # Switch to this source for your IdP
    ntk cfg set :sso.\"saml-idp\".\"<IdP ID>\".auth "autoselect"

