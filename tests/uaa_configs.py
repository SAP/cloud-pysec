''' test uaa configurations '''

INVALID = {
    'uaa_url_undefined': {
        'clientid': 'xs2.node',
        'clientsecret': 'nodeclientsecret',
        'verificationkey': 'NODETESTSECRET',
        'xsappname': 'node_unittest_app',
        'identityzone': 'test-idz',
        'tags': ['xsuaa_url_undefined'],
        'uaadomain': 'api.cf.test.com'
    },
    'uaa_clientid_undefined': {
        'url': 'http://sap-login-test.cfapps.neo.ondemand.com',
        'clientsecret': 'nodeclientsecret',
        'verificationkey': 'NODETESTSECRET',
        'xsappname': 'node_unittest_app',
        'identityzone': 'test-idz',
        'tags': ['xsuaa_clientid_undefined'],
        'uaadomain': 'api.cf.test.com'
    },
    'uaa_clientsecret_undefined': {
        'url': 'http://sap-login-test.cfapps.neo.ondemand.com',
        'clientid': 'xs2.node',
        'verificationkey': 'NODETESTSECRET',
        'xsappname': 'node_unittest_app',
        'identityzone': 'test-idz',
        'tags': ['xsuaa_clientsecret_undefined'],
        'uaadomain': 'api.cf.test.com'
    },
    'uaa_xsappname_undefined': {
        'url': 'http://sap-login-test.cfapps.neo.ondemand.com',
        'clientid': 'xs2.node',
        'clientsecret': 'nodeclientsecret',
        'verificationkey': 'NODETESTSECRET',
        'identityzone': 'test-idz',
        'tags': ['xsuaa_clientsecret_undefined'],
        'uaadomain': 'api.cf.test.com'
    },
    'uaa_broker_plan_wrong_suffix': {
        'clientid': 'sb-xssectest!t4',
        'verificationkey': 'NODETESTSECRET',
        'xsappname': 'uaa',
        'identityzone': 'test-idz',
        'trustedclientidsuffix': 'hugo',
        'clientsecret': 'z431EZmJWiuA/yINKXGewGR/wo99JKiVKAzG7yRyUHldI'
                        'FUBiZx5SOMxvS2nqwwDzK6sqX2Hx2i2\nadgJjtIqgA==',
        'url': 'https://test.home.me/uaa',
        'tags': ['xsuaa_broker_plan_wrong_suffix'],
        'uaadomain': 'api.cf.test.com'
    },
    'uaa_verificationkey_invalid': {
        'clientid': 'sb-clone2!b1|LR-master!b1',
        'verificationkey': 'invalid',
        'xsappname': 'uaa',
        'identityzone': 'paas',
        'clientsecret': 'z431EZmJWiuA/yINKXGewGR/wo99JKiVKAzG7yRyUHldI'
                        'FUBiZx5SOMxvS2nqwwDzK6sqX2Hx2i2\nadgJjtIqgA==',
        'url': 'http://paas.localhost:8080/uaa-security',
        'tags': ['xsuaa_application_plan'],
        'uaadomain': 'api.cf.test.com'
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
        'url': 'https://test.home.me/uaa',
        'tags': ['xsuaa'],
        'uaadomain': 'api.cf.test.com'
    },
    'uaa_foreign_idz': {
        'clientid': 'sb-xssectest',
        'verificationkey': 'NODETESTSECRET',
        'xsappname': 'uaa',
        'identityzoneid': 'foreign-idz',
        'clientsecret': 'z431EZmJWiuA/yINKXGewGR/wo99JKiVKAzG7yRyUHld'
                        'IFUBiZx5SOMxvS2nqwwDzK6sqX2Hx2i2\nadgJjtIqgA==',
        'url': 'https://test.home.me/uaa',
        'tags': ['xsuaa_foreign_idz'],
        'uaadomain': 'api.cf.test.com'
    },
    'uaa_foreign_clientid': {
        'clientid': 'foreign-clientid',
        'verificationkey': 'NODETESTSECRET',
        'xsappname': 'uaa',
        'identityzone': 'test-idz',
        'clientsecret': 'z431EZmJWiuA/yINKXGewGR/wo99JKiVKAzG7yRyUHldI'
                        'FUBiZx5SOMxvS2nqwwDzK6sqX2Hx2i2\nadgJjtIqgA==',
        'url': 'https://test.home.me/uaa',
        'tags': ['xsuaa_foreign_clientid'],
        'uaadomain': 'api.cf.test.com'
    },
    'uaa_foreign_idz_clientid': {
        'clientid': 'foreign-clientid',
        'verificationkey': 'NODETESTSECRET',
        'xsappname': 'uaa',
        'identityzone': 'foreign-idz',
        'clientsecret': 'z431EZmJWiuA/yINKXGewGR/wo99JKiVKAzG7yRyUHld'
                        'IFUBiZx5SOMxvS2nqwwDzK6sqX2Hx2i2\nadgJjtIqgA==',
        'url': 'https://test.home.me/uaa',
        'tags': ['xsuaa_foreign_idz_clientid'],
        'uaadomain': 'api.cf.test.com'
    },
    'uaa_cc': {
        'clientid': 'sb-xssectest',
        'verificationkey': 'NODETESTSECRET',
        'xsappname': 'uaa',
        'identityzone': 'test-idz',
        'clientsecret': 'z431EZmJWiuA/yINKXGewGR/wo99JKiVKAzG7yRyUHld'
                        'IFUBiZx5SOMxvS2nqwwDzK6sqX2Hx2i2\nadgJjtIqgA==',
        'url': 'https://test.home.me/uaa',
        'tags': ['xsuaa_cc'],
        'uaadomain': 'api.cf.test.com'
    },
    'uaa_bearer': {
        'clientid': 'sb-xssectest',
        'verificationkey': 'NODETESTSECRET',
        'xsappname': 'admin',
        'identityzone': 'test-idz',
        'clientsecret': 'UBHlAbnLhn+PiTc7xWG7s1yb+bTkXOjvDtBRbDykXLS2c'
                        'DQIMjSzXZccV6dweeIZJphnqhqJ5MVz\niAdePOsZEQ==',
        'url': 'https://mo-dd9396c2c.mo.sap.corp:30032/uaa-security',
        'tags': ['xsuaa_bearer'],
        'uaadomain': 'api.cf.test.com'
    },
    'uaa_broker_plan': {
        'clientid': 'sb-xssectest!b4',
        'verificationkey': 'NODETESTSECRET',
        'xsappname': 'uaa',
        'identityzone': 'test-idz',
        'trustedclientidsuffix': '|sb-xssectest!b4',
        'clientsecret': 'z431EZmJWiuA/yINKXGewGR/wo99JKiVKAzG7yRyUHldI'
                        'FUBiZx5SOMxvS2nqwwDzK6sqX2Hx2i2\nadgJjtIqgA==',
        'url': 'https://test.home.me/uaa',
        'tags': ['xsuaa_broker_plan'],
        'uaadomain': 'api.cf.test.com'
    },
    'uaa_application_plan': {
        'clientid': 'sb-xssectest!t4',
        'verificationkey': 'NODETESTSECRET',
        'xsappname': 'uaa',
        'identityzone': 'paas-idz',
        'clientsecret': 'z431EZmJWiuA/yINKXGewGR/wo99JKiVKAzG7yRyUHldI'
                        'FUBiZx5SOMxvS2nqwwDzK6sqX2Hx2i2\nadgJjtIqgA==',
        'url': 'https://test.home.me/uaa',
        'tags': ['xsuaa_application_plan'],
        'uaadomain': 'api.cf.test.com'
    },
    'uaa_new_token_structure': {
        'clientid': 'sb-clone2!b1|LR-master!b1',
        'verificationkey': 'secret',
        'xsappname': 'uaa',
        'identityzone': 'paas',
        'clientsecret': 'z431EZmJWiuA/yINKXGewGR/wo99JKiVKAzG7yRyUHldI'
                        'FUBiZx5SOMxvS2nqwwDzK6sqX2Hx2i2\nadgJjtIqgA==',
        'url': 'http://paas.localhost:8080/uaa-security',
        'tags': ['xsuaa_application_plan'],
        'uaadomain': 'api.cf.test.com'
    },
    'uaa_no_verification_key': {
        'clientid': 'sb-xssectest',
        'xsappname': 'uaa',
        'identityzone': 'test-idz-name',
        'identityzoneid': 'test-idz',
        'clientsecret': 'z431EZmJWiuA/yINKXGewGR/wo99JKiVKAzG7yRyUHld'
                        'IFUBiZx5SOMxvS2nqwwDzK6sqX2Hx2i2\nadgJjtIqgA==',
        'url': 'https://test.me/uaa',
        'tags': ['xsuaa'],
        'uaadomain': 'api.cf.test.com'
    },
    'uaa_no_verification_key_other_domain': {
        'clientid': 'sb-xssectest',
        'xsappname': 'uaa',
        'identityzone': 'test-idz-name',
        'identityzoneid': 'test-idz',
        'clientsecret': 'z431EZmJWiuA/yINKXGewGR/wo99JKiVKAzG7yRyUHld'
                        'IFUBiZx5SOMxvS2nqwwDzK6sqX2Hx2i2\nadgJjtIqgA==',
        'url': 'https://test.me/uaa',
        'tags': ['xsuaa'],
        'uaadomain': 'api.cf2.test.com'
    },
    'uaa_xsa_environment': {
        'clientid': 'sb-xssectest',
        'xsappname': 'uaa',
        'identityzone': 'uaa',
        'identityzoneid': 'uaa',
        'clientsecret': 'z431EZmJWiuA/yINKXGewGR/wo99JKiVKAzG7yRyUHld'
                        'IFUBiZx5SOMxvS2nqwwDzK6sqX2Hx2i2\nadgJjtIqgA==',
        'url': 'http://localhost:8080/uaa',
        'verificationkey': '-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQAB-----END PUBLIC KEY-----',
        'tags': ['xsuaa']
    }
}
