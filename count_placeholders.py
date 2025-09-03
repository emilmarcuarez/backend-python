import re

with open('app_flask.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Find the HTML template section
start = content.find('html_out = """')
end = content.find('""" % (')
html_template = content[start:end]

# Count %s and %d placeholders
placeholders = re.findall(r'%[sd]', html_template)
print(f'Total placeholders found: {len(placeholders)}')

# Also count the arguments
args_start = content.find('""" % (')
args_end = content.find(')')
args_section = content[args_start:args_end]

# Count commas to estimate number of arguments (rough estimate)
# This is not perfect but gives us an idea
lines = args_section.split('\n')
arg_count = 0
for line in lines:
    if line.strip() and not line.strip().startswith('#'):
        # Count non-comment lines that contain actual arguments
        if any(char in line for char in ['rep_obj', 'esc(', 'score_val', 'wp_', 'tls_', 'server_', 'host_', 'rest_', 'headers_', 'cookies_', 'mixed_', 'open_dirs_', 'backups_', 'perf_', 'privacy_', 'seo_', 'admin_', 'wp_cron_', 'oembed_', 'jwt_', 'graphql_', 'wc_rest_', 'acf_rest_', 'jquery_', 'risk_', 'casino_', 'spam_', 'malicious_', 'links_', 'scripts_', 'images_', 'resources_', 'hidden_', 'gsb_', 'vt_', 'uh_', 'pt_', 'lcp_', 'cls_', 'inp_', 'psi_', 'broken_', 'missing_', 'forms_', 'buttons_', 'ux_', 'media_', 'accessibility_', 'performance_', 'viol_', 'heur_', 'recs_', 'infected_', 'urls_', 'evid_', 'acciones_', 'json.dumps']):
            arg_count += 1

print(f'Estimated arguments: {arg_count}')

# Let's count the actual arguments more precisely
args_text = content[args_start:args_end]

# Count arguments by looking for lines that contain actual values
arg_count = 0
for line in args_text.split('\n'):
    line = line.strip()
    # Skip empty lines, comments, and the opening/closing lines
    if (line and 
        not line.startswith('#') and 
        not line.startswith('""" % (') and 
        not line.endswith(')') and
        not line.startswith(')')):
        # Count lines that contain actual arguments (not just comments)
        if (',' in line or 
            line.endswith(',') or 
            any(keyword in line for keyword in ['rep_obj', 'esc(', 'score_val', 'wp_', 'tls_', 'server_', 'host_', 'rest_', 'headers_', 'cookies_', 'mixed_', 'open_dirs_', 'backups_', 'perf_', 'privacy_', 'seo_', 'admin_', 'wp_cron_', 'oembed_', 'jwt_', 'graphql_', 'wc_rest_', 'acf_rest_', 'jquery_', 'risk_', 'casino_', 'spam_', 'malicious_', 'links_', 'scripts_', 'images_', 'resources_', 'hidden_', 'gsb_', 'vt_', 'uh_', 'pt_', 'lcp_', 'cls_', 'inp_', 'psi_', 'broken_', 'missing_', 'forms_', 'buttons_', 'ux_', 'media_', 'accessibility_', 'performance_', 'viol_', 'heur_', 'recs_', 'infected_', 'urls_', 'evid_', 'acciones_', 'json.dumps', 'alert_html', 'yn(', 'str(', 'html.escape'])):
            arg_count += 1

print(f'Actual arguments: {arg_count}')
print(f'Placeholders: {len(placeholders)}')
print(f'Difference: {len(placeholders) - arg_count}')

# Let's also print the first few and last few placeholders to see the pattern
print(f'\nFirst 10 placeholders: {placeholders[:10]}')
print(f'Last 10 placeholders: {placeholders[-10:]}')
