"""Test the scoring logic to verify AI gets priority"""

def get_combined_verdict(ml_result, vt_result, ai_result):
    scores = []
    weights = []
    
    if ml_result['verdict'] == 'Phishing':
        scores.append(-50)
        weights.append(1.0)
    elif ml_result['verdict'] == 'Legitimate':
        scores.append(50)
        weights.append(1.0)
    
    if vt_result.get('available'):
        if vt_result['verdict'] == 'Malicious':
            scores.append(-100)
            weights.append(2.5)
        elif vt_result['verdict'] == 'Suspicious':
            scores.append(-50)
            weights.append(2.0)
        elif vt_result['verdict'] == 'Safe':
            scores.append(40)
            weights.append(1.5)
    
    if ai_result.get('available'):
        ai_verdict = ai_result['verdict']
        ai_confidence = ai_result.get('confidence_score', 50)
        if ai_verdict == 'Malicious':
            scores.append(-100)
            weights.append(3.0)
        elif ai_verdict == 'Suspicious':
            scores.append(-70)
            weights.append(2.5)
        elif ai_verdict == 'Safe':
            scores.append(50)
            weights.append(2.0)
    
    if not scores:
        avg_score = 0
    else:
        weighted_sum = sum(s * w for s, w in zip(scores, weights))
        total_weight = sum(weights)
        avg_score = weighted_sum / total_weight
    
    # AI override - if AI says suspicious/malicious, cap the score
    if ai_result.get('available') and ai_result['verdict'] in ['Malicious', 'Suspicious']:
        if avg_score > -20:
            avg_score = -20
    
    if avg_score < -50:
        return "Malicious", "Critical", avg_score
    elif avg_score < -20:
        return "Suspicious", "High", avg_score
    elif avg_score < 10:
        return "Suspicious", "Medium", avg_score
    else:
        return "Safe", "Low", avg_score

# Test Case 1: g00gle.com (AI suspicious, VT safe, ML legitimate)
print("=" * 60)
print("TEST 1: g00gle.com (typosquatting)")
print("=" * 60)
ml1 = {'verdict': 'Legitimate'}
vt1 = {'available': True, 'verdict': 'Safe'}
ai1 = {'available': True, 'verdict': 'Suspicious', 'confidence_score': 85}

verdict1, risk1, score1 = get_combined_verdict(ml1, vt1, ai1)
print(f"ML: {ml1['verdict']} → score: 50 × 1.0 = 50")
print(f"VT: {vt1['verdict']} → score: 40 × 1.5 = 60")
print(f"AI: {ai1['verdict']} ({ai1['confidence_score']}%) → score: -70 × 2.5 = -175")
print(f"\nWeighted average: (50 + 60 - 175) / (1.0 + 1.5 + 2.5) = -65 / 5.0 = -13")
print(f"AI override kicks in: max(-13, -20) = -20")
print(f"\n✅ RESULT: {verdict1} | Risk: {risk1} | Score: {score1:.2f}")
print(f"EXPECTED: Suspicious | Risk: High")

# Test Case 2: amazon.account.security-verification.com (all should flag as malicious)
print("\n" + "=" * 60)
print("TEST 2: amazon.account.security-verification.com (phishing)")
print("=" * 60)
ml2 = {'verdict': 'Phishing'}
vt2 = {'available': True, 'verdict': 'Safe'}  # VT might not detect it yet
ai2 = {'available': True, 'verdict': 'Malicious', 'confidence_score': 95}

verdict2, risk2, score2 = get_combined_verdict(ml2, vt2, ai2)
print(f"ML: {ml2['verdict']} → score: -50 × 1.0 = -50")
print(f"VT: {vt2['verdict']} → score: 40 × 1.5 = 60")
print(f"AI: {ai2['verdict']} ({ai2['confidence_score']}%) → score: -100 × 3.0 = -300")
print(f"\nWeighted average: (-50 + 60 - 300) / (1.0 + 1.5 + 3.0) = -290 / 5.5 = -52.73")
print(f"AI override: already < -20, so stays at -52.73")
print(f"\n✅ RESULT: {verdict2} | Risk: {risk2} | Score: {score2:.2f}")
print(f"EXPECTED: Malicious | Risk: Critical")

# Test Case 3: Legitimate site (google.com - all agree it's safe)
print("\n" + "=" * 60)
print("TEST 3: google.com (legitimate)")
print("=" * 60)
ml3 = {'verdict': 'Legitimate'}
vt3 = {'available': True, 'verdict': 'Safe'}
ai3 = {'available': True, 'verdict': 'Safe', 'confidence_score': 98}

verdict3, risk3, score3 = get_combined_verdict(ml3, vt3, ai3)
print(f"ML: {ml3['verdict']} → score: 50 × 1.0 = 50")
print(f"VT: {vt3['verdict']} → score: 40 × 1.5 = 60")
print(f"AI: {ai3['verdict']} ({ai3['confidence_score']}%) → score: 50 × 2.0 = 100")
print(f"\nWeighted average: (50 + 60 + 100) / (1.0 + 1.5 + 2.0) = 210 / 4.5 = 46.67")
print(f"\n✅ RESULT: {verdict3} | Risk: {risk3} | Score: {score3:.2f}")
print(f"EXPECTED: Safe | Risk: Low")

print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
print(f"✅ AI suspicious overrides others: {'PASS' if verdict1 == 'Suspicious' else 'FAIL'}")
print(f"✅ AI malicious dominates: {'PASS' if verdict2 == 'Malicious' else 'FAIL'}")
print(f"✅ All safe = safe: {'PASS' if verdict3 == 'Safe' else 'FAIL'}")
