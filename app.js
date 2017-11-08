var entropy = require('shannon-entropy');
const certstream = require('certstream');
const tqdm = require('ntqdm');

log_suspicious = 'suspicious_domains.log'

suspicious_keywords = [
    'login',
    'log-in',
    'account',
    'verification',
    'verify',
    'support',
    'activity',
    'security',
    'update',
    'authentication',
    'authenticate',
    'wallet',
    'alert',
    'purchase',
    'transaction',
    'recover',
    'live',
    'office'
    ]

highly_suspicious = [
    'paypal',
    'paypol',
    'poypal',
    'twitter',
    'appleid',
    'gmail',
    'outlook',
    'protonmail',
    'amazon',
    'facebook',
    'microsoft',
    'windows',
    'cgi-bin',
    'localbitcoin',
    'icloud',
    'iforgot',
    'isupport',
    'kraken',
    'bitstamp',
    'bittrex',
    'blockchain',
    '.com-',
    '-com.',
    '.net-',
    '.org-',
    '.gov-',
    '.gouv-',
    '-gouv-'
    ]

suspicious_tld = [
    '.ga',
    '.gq',
    '.ml',
    '.cf',
    '.tk',
    '.xyz',
    '.pw',
    '.cc',
    '.club',
    '.work',
    '.top',
    '.support',
    '.bank',
    '.info',
    '.study',
    '.party',
    '.click',
    '.country',
    '.stream',
    '.gdn',
    '.mom',
    '.xin',
    '.kim',
    '.men',
    '.loan',
    '.download',
    '.racing',
    '.online',
    '.ren',
    '.gb',
    '.win',
    '.review',
    '.vip',
    '.party',
    '.tech',
    '.science'
    ]

pbar = tqdm(desc='certificate_update')

function score_domain(domain){
	score = 0
	suspicious_tld.forEach(function(tld){
		if domain.endswith(tld):
            score += 20
	});
    
    suspicious_keywords.forEach(function(keyword){
    	if domain.includes(keyword):
            score += 25
    });
    
    highly_suspicious.forEach(function(keyword){
    	if(domain.includes(keyword)){
    		score += 60
    	}
    });

    score += entropy(domain)*50;

    if(domain.includes('xn--') && (domain.split('-').length-1) >= 4){
        score += 20
    }
    return score
}    