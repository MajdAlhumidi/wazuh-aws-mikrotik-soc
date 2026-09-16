import chromadb
from chromadb.utils import embedding_functions
from schema import IncidentRecord

# 1. إعداد التخزين الدائم
client = chromadb.PersistentClient(path="./incident_vector_db")

# 2. تحميل نموذج التضمين الدلالي
emb_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
    model_name="all-MiniLM-L6-v2"
)

# 3. إنشاء أو فتح المجموعة
collection = client.get_or_create_collection(
    name="security_incidents",
    embedding_function=emb_fn,
    metadata={"hnsw:space": "cosine"}
)

def store_incidents(records: list[IncidentRecord]):
    ids = [r.incident_id for r in records]
    docs = [r.to_document_text() for r in records]
    metas = [r.to_metadata() for r in records]
    
    collection.add(ids=ids, documents=docs, metadatas=metas)
    print(f"[+] Successfully stored {len(records)} incidents.")

def search_incidents(query_text: str, n_results: int = 1, filter_type: str = None):
    where_filter = {"classification": filter_type} if filter_type else None
    
    results = collection.query(
        query_texts=[query_text],
        n_results=n_results,
        where=where_filter
    )
    return results

if __name__ == "__main__":
    # عينات اختبارية: هجوم حقيقي + إنذار خاطئ
    tp_incident = IncidentRecord(
        incident_id="INC-2024-101",
        rule_name="Suspicious PowerShell Encoded Command",
        classification="true_positive",
        alert_summary="PowerShell executed with Base64 encoded payload attempting credential dumping.",
        source_ip="10.10.4.15",
        destination_ip="185.220.101.5",
        user_account="svc_backup",
        raw_logs="powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgA...",
        analyst_notes="Attacker used compromised service account to dump LSASS memory."
    )

    fp_incident = IncidentRecord(
        incident_id="INC-2024-102",
        rule_name="Suspicious PowerShell Encoded Command",
        classification="false_positive",
        alert_summary="PowerShell execution detected running encoded script block from SCCM.",
        source_ip="10.10.1.20",
        destination_ip="10.10.4.15",
        user_account="SYSTEM",
        raw_logs="C:\\Windows\\CCM\\SystemTemp\\script.ps1 -Enc WwBTAHkAcwB0AGUAbQ...",
        analyst_notes="Legitimate SCCM management script for monthly patch deployment."
    )

    # تخزين البيانات
    store_incidents([tp_incident, fp_incident])

    # اختبار استعلام جديد للبحث عن أقرب False Positive
    test_query = "PowerShell script running periodic maintenance task via management software"
    print("\n[*] Querying vector store for similar incidents...")
    res = search_incidents(test_query, n_results=1, filter_type="false_positive")
    
    print("\n--- Match Found ---")
    print("ID:", res["ids"][0][0])
    print("Analyst Notes:", res["metadatas"][0][0]["analyst_notes"])
    print("Distance:", res["distances"][0][0])
