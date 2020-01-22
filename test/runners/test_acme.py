# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring

def _read(path, mode='r'):
    with open(path, mode) as f:
        return f.read()


def test_sign(runners):
    ret = runners["acme.sign"](_read('test/fixtures/example.csr'))

    assert ret['text'] == '----'
