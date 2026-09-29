# Zeek policy for the watch-only NeuraWall node on the NEXORA host.
@load policy/tuning/json-logs.zeek

# The OCI VCN: lets conn.log's local_orig/local_resp mark inbound vs outbound traffic.
redef Site::local_nets += { 10.0.0.0/8 };

# Rotate hourly and delete rotated files: the agent tails the live logs, so old ones
# are never needed and disk use stays flat.
redef Log::default_rotation_interval = 1 hr;
redef Log::default_rotation_postprocessor_cmd = "rm -f";
