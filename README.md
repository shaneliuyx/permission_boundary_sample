# permission_boundary_sample
####Some sample codes for IAM permission boundary
####The following 2 lambda functions need environment variables:
   -Functions: change_boundary_doc.py and handle_task_queue.py
   -Envionment variables:
      -POLICY_ARN	-- the arn of policy (policy boundary)
      -QUEUE	      -- the name of SQS queue
   
