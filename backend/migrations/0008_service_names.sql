-- Service identity is independent of the synthetic-data classification.
UPDATE events SET service=CASE service WHEN 'demo-nginx' THEN 'nginx' WHEN 'demo-apache' THEN 'apache-httpd' WHEN 'demo-ssh' THEN 'sshd' END WHERE service IN('demo-nginx','demo-apache','demo-ssh');
UPDATE incidents SET group_key=jsonb_set(group_key,'{service}',to_jsonb(CASE group_key->>'service' WHEN 'demo-nginx' THEN 'nginx' WHEN 'demo-apache' THEN 'apache-httpd' WHEN 'demo-ssh' THEN 'sshd' END)) WHERE group_key->>'service' IN('demo-nginx','demo-apache','demo-ssh');
