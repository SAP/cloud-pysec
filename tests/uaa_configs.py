''' test uaa configurations '''

INVALID = {
    'uaa_url_undefined': {
        'clientid': 'xs2.node',
        'clientsecret': 'nodeclientsecret',
        'verificationkey': 'NODETESTSECRET',
        'xsappname': 'node_unittest_app',
        'identityzone': 'test-idz',
        'tags': ['xsuaa_url_undefined']
    },
    'uaa_clientid_undefined': {
        'url': 'http://sap-login-test.cfapps.neo.ondemand.com',
        'clientsecret': 'nodeclientsecret',
        'verificationkey': 'NODETESTSECRET',
        'xsappname': 'node_unittest_app',
        'identityzone': 'test-idz',
        'tags': ['xsuaa_clientid_undefined']
    },
    'uaa_clientsecret_undefined': {
        'url': 'http://sap-login-test.cfapps.neo.ondemand.com',
        'clientid': 'xs2.node',
        'verificationkey': 'NODETESTSECRET',
        'xsappname': 'node_unittest_app',
        'identityzone': 'test-idz',
        'tags': ['xsuaa_clientsecret_undefined']
    },
    'uaa_verificationkey_undefined': {
        'url': 'http://sap-login-test.cfapps.neo.ondemand.com',
        'clientid': 'xs2.node',
        'clientsecret': 'nodeclientsecret',
        'xsappname': 'node_unittest_app',
        'identityzone': 'test-idz',
        'tags': ['xsuaa_clientsecret_undefined']
    },
    'uaa_xsappname_undefined': {
        'url': 'http://sap-login-test.cfapps.neo.ondemand.com',
        'clientid': 'xs2.node',
        'clientsecret': 'nodeclientsecret',
        'verificationkey': 'NODETESTSECRET',
        'identityzone': 'test-idz',
        'tags': ['xsuaa_clientsecret_undefined']
    },
    'uaa_broker_plan_wrong_suffix': {
        'clientid': 'sb-xssectest!t4',
        'verificationkey': 'NODETESTSECRET',
        'xsappname': 'uaa',
        'identityzone': 'test-idz',
        'trustedclientidsuffix': 'hugo',
        'clientsecret': 'z431EZmJWiuA/yINKXGewGR/wo99JKiVKAzG7yRyUHldI'
                        'FUBiZx5SOMxvS2nqwwDzK6sqX2Hx2i2\nadgJjtIqgA==',
        'url': 'https://lu356076.dhcp.wdf.sap.corp:30332/uaa-security',
        'tags': ['xsuaa_broker_plan_wrong_suffix']
    },
    'uaa_verificationkey_invalid': {
        'clientid': 'sb-clone2!b1|LR-master!b1',
        'verificationkey': 'invalid',
        'xsappname': 'uaa',
        'identityzone': 'paas',
        'clientsecret': 'z431EZmJWiuA/yINKXGewGR/wo99JKiVKAzG7yRyUHldI'
                        'FUBiZx5SOMxvS2nqwwDzK6sqX2Hx2i2\nadgJjtIqgA==',
        'url': 'http://paas.localhost:8080/uaa-security',
        'tags': ['xsuaa_application_plan']
    }
}
VALID = {
    'uaa': {
        'clientid': 'sb-xssectest',
        'verificationkey': 'NODETESTSECRET',
        'xsappname': 'uaa',
        'identityzone': 'test-idz-name',
        'identityzoneid': 'test-idz',
        'clientsecret': 'z431EZmJWiuA/yINKXGewGR/wo99JKiVKAzG7yRyUHld'
                        'IFUBiZx5SOMxvS2nqwwDzK6sqX2Hx2i2\nadgJjtIqgA==',
        'url': 'https://lu356076.dhcp.wdf.sap.corp:30332/uaa-security',
        'tags': ['xsuaa']
    },
    'uaa_foreign_idz': {
        'clientid': 'sb-xssectest',
        'verificationkey': 'NODETESTSECRET',
        'xsappname': 'uaa',
        'identityzoneid': 'foreign-idz',
        'clientsecret': 'z431EZmJWiuA/yINKXGewGR/wo99JKiVKAzG7yRyUHld'
                        'IFUBiZx5SOMxvS2nqwwDzK6sqX2Hx2i2\nadgJjtIqgA==',
        'url': 'https://lu356076.dhcp.wdf.sap.corp:30332/uaa-security',
        'tags': ['xsuaa_foreign_idz']
    },
    'uaa_foreign_clientid': {
        'clientid': 'foreign-clientid',
        'verificationkey': 'NODETESTSECRET',
        'xsappname': 'uaa',
        'identityzone': 'test-idz',
        'clientsecret': 'z431EZmJWiuA/yINKXGewGR/wo99JKiVKAzG7yRyUHldI'
                        'FUBiZx5SOMxvS2nqwwDzK6sqX2Hx2i2\nadgJjtIqgA==',
        'url': 'https://lu356076.dhcp.wdf.sap.corp:30332/uaa-security',
        'tags': ['xsuaa_foreign_clientid']
    },
    'uaa_foreign_idz_clientid': {
        'clientid': 'foreign-clientid',
        'verificationkey': 'NODETESTSECRET',
        'xsappname': 'uaa',
        'identityzone': 'foreign-idz',
        'clientsecret': 'z431EZmJWiuA/yINKXGewGR/wo99JKiVKAzG7yRyUHld'
                        'IFUBiZx5SOMxvS2nqwwDzK6sqX2Hx2i2\nadgJjtIqgA==',
        'url': 'https://lu356076.dhcp.wdf.sap.corp:30332/uaa-security',
        'tags': ['xsuaa_foreign_idz_clientid']
    },
    'uaa_cc': {
        'clientid': 'sb-xssectest',
        'verificationkey': 'NODETESTSECRET',
        'xsappname': 'uaa',
        'identityzone': 'test-idz',
        'clientsecret': 'z431EZmJWiuA/yINKXGewGR/wo99JKiVKAzG7yRyUHld'
                        'IFUBiZx5SOMxvS2nqwwDzK6sqX2Hx2i2\nadgJjtIqgA==',
        'url': 'https://lu356076.dhcp.wdf.sap.corp:30332/uaa-security',
        'tags': ['xsuaa_cc']
    },
    'uaa_bearer': {
        'clientid': 'sb-xssectest',
        'verificationkey': 'NODETESTSECRET',
        'xsappname': 'admin',
        'identityzone': 'test-idz',
        'clientsecret': 'UBHlAbnLhn+PiTc7xWG7s1yb+bTkXOjvDtBRbDykXLS2c'
                        'DQIMjSzXZccV6dweeIZJphnqhqJ5MVz\niAdePOsZEQ==',
        'url': 'https://mo-dd9396c2c.mo.sap.corp:30032/uaa-security',
        'tags': ['xsuaa_bearer']
    },
    'uaa_broker_plan': {
        'clientid': 'sb-xssectest!b4',
        'verificationkey': 'NODETESTSECRET',
        'xsappname': 'uaa',
        'identityzone': 'test-idz',
        'trustedclientidsuffix': '|sb-xssectest!b4',
        'clientsecret': 'z431EZmJWiuA/yINKXGewGR/wo99JKiVKAzG7yRyUHldI'
                        'FUBiZx5SOMxvS2nqwwDzK6sqX2Hx2i2\nadgJjtIqgA==',
        'url': 'https://lu356076.dhcp.wdf.sap.corp:30332/uaa-security',
        'tags': ['xsuaa_broker_plan']
    },
    'uaa_application_plan': {
        'clientid': 'sb-xssectest!t4',
        'verificationkey': 'NODETESTSECRET',
        'xsappname': 'uaa',
        'identityzone': 'paas-idz',
        'clientsecret': 'z431EZmJWiuA/yINKXGewGR/wo99JKiVKAzG7yRyUHldI'
                        'FUBiZx5SOMxvS2nqwwDzK6sqX2Hx2i2\nadgJjtIqgA==',
        'url': 'https://lu356076.dhcp.wdf.sap.corp:30332/uaa-security',
        'tags': ['xsuaa_application_plan']
    },
    'uaa_new_token_structure': {
        'clientid': 'sb-clone2!b1|LR-master!b1',
        'verificationkey': 'secret',
        'xsappname': 'uaa',
        'identityzone': 'paas',
        'clientsecret': 'z431EZmJWiuA/yINKXGewGR/wo99JKiVKAzG7yRyUHldI'
                        'FUBiZx5SOMxvS2nqwwDzK6sqX2Hx2i2\nadgJjtIqgA==',
        'url': 'http://paas.localhost:8080/uaa-security',
        'tags': ['xsuaa_application_plan']
    }
}
