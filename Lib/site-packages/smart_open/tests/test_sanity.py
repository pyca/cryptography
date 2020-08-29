import unittest

import boto3
import moto


@moto.mock_s3()
def setUpModule():
    bucket = boto3.resource('s3').create_bucket(Bucket='mybucket')

    bucket.wait_until_exists()


@moto.mock_s3()
def tearDownModule():
    resource = boto3.resource('s3')
    bucket = resource.Bucket('mybucket')
    try:
        bucket.delete()
    except resource.meta.client.exceptions.NoSuchBucket:
        pass
    bucket.wait_until_not_exists()


@moto.mock_s3()
class Test(unittest.TestCase):

    def test(self):
        resource = boto3.resource('s3')

        bucket = resource.Bucket('mybucket')
        self.assertEqual(bucket.name, 'mybucket')

        expected = b'hello'
        resource.Object('mybucket', 'mykey').put(Body=expected)

        actual = resource.Object('mybucket', 'mykey').get()['Body'].read()
        self.assertEqual(expected, actual)

    def tearDown(self):
        boto3.resource('s3').Object('mybucket', 'mykey').delete()
