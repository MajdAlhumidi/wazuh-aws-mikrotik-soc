from vector_store import search_incidents

def investigate_historical_incidents(alert_context: str) -> str:
    """
    أداة يستدعيها الـ Agent للبحث عن حوادث وتنبيهات أمنية سابقة مشابهة
    لمعرفة كيف تم تصنيفها سابقاً (True Positive أو False Positive).
    """
    try:
        # البحث عن أقرب حادثتين مشابهتين
        results = search_incidents(query_text=alert_context, n_results=2)
        
        if not results or not results["documents"][0]:
            return "No similar historical incidents found."

        output = "--- HISTORICAL SIMILAR INCIDENTS FOUND ---\n"
        for i in range(len(results["documents"][0])):
            doc = results["documents"][0][i]
            meta = results["metadatas"][0][i]
            distance = results["distances"][0][i]
            
            output += (
                f"\n[Incident #{i+1}]\n"
                f"- ID: {meta.get('incident_id')}\n"
                f"- Previous Classification: {meta.get('classification').upper()}\n"
                f"- Detection Rule: {meta.get('rule_name')}\n"
                f"- Similarity Distance: {round(distance, 4)} (Closer to 0 means more identical)\n"
                f"- Analyst Notes: {meta.get('analyst_notes')}\n"
                f"- Historical Context:\n{doc}\n"
                "-----------------------------------------\n"
            )
        return output
    except Exception as e:
        return f"Error executing semantic search: {str(e)}"
