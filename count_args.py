import re

with open('app_flask.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Find the arguments section
args_start = content.find('""" % (')
args_end = content.find(')')
args_section = content[args_start:args_end]

# Split by lines and count actual arguments
lines = args_section.split('\n')
arg_count = 0
for line in lines:
    line = line.strip()
    # Skip empty lines, comments, and the opening/closing lines
    if (line and 
        not line.startswith('#') and 
        not line.startswith('""" % (') and 
        not line.endswith(')') and
        not line.startswith(')')):
        # Count lines that contain actual arguments
        if (line.endswith(',') or 
            any(keyword in line for keyword in ['rep_obj', 'esc(', 'score_val', 'wp_', 'tls_', 'server_', 'host_', 'rest_', 'headers_', 'cookies_', 'mixed_', 'open_dirs_', 'backups_', 'perf_', 'privacy_', 'seo_', 'admin_', 'wp_cron_', 'oembed_', 'jwt_', 'graphql_', 'wc_rest_', 'acf_rest_', 'jquery_', 'risk_', 'casino_', 'spam_', 'malicious_', 'links_', 'scripts_', 'images_', 'resources_', 'hidden_', 'gsb_', 'vt_', 'uh_', 'pt_', 'lcp_', 'cls_', 'inp_', 'psi_', 'broken_', 'missing_', 'forms_', 'buttons_', 'ux_', 'media_', 'accessibility_', 'performance_', 'viol_', 'heur_', 'recs_', 'infected_', 'urls_', 'evid_', 'acciones_', 'json.dumps', 'alert_html', 'yn(', 'str(', 'html.escape', 'Sí', 'No', 'Abierto', 'Restringido', 'Inseguro', 'OK', 'Expuesto'])):
            arg_count += 1

print(f'Arguments found: {arg_count}')

# Let's also try a different approach - count commas in the arguments section
# This is more reliable
args_text = content[args_start:args_end]
# Remove comments
lines = args_text.split('\n')
clean_lines = []
for line in lines:
    if not line.strip().startswith('#'):
        clean_lines.append(line)
clean_text = '\n'.join(clean_lines)

# Count commas (each argument is separated by a comma)
comma_count = clean_text.count(',')
print(f'Commas found: {comma_count}')
print(f'Estimated arguments (commas + 1): {comma_count + 1}')

# Let's also count the placeholders again to be sure
html_start = content.find('html_out = """')
html_end = content.find('""" % (')
html_template = content[html_start:html_end]
placeholders = re.findall(r'%[sd]', html_template)
print(f'Placeholders: {len(placeholders)}')
print(f'Difference: {len(placeholders) - (comma_count + 1)}')
