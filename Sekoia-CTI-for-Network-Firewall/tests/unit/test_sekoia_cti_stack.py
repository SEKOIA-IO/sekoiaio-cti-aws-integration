import aws_cdk as core
import aws_cdk.assertions as assertions

from sekoia_cti.sekoia_cti_stack import SekoiaCtiStack

# example tests. To run these tests, uncomment this file along with the example
# resource in sekoia_cti/sekoia_cti_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = SekoiaCtiStack(app, "sekoia-cti")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
