# Step 8: Create Vector Store with Progress Monitoring (CORRIGÉ)
print("Creating vector embeddings with progress monitoring...")
print("=" * 60)

import time  # AJOUT OBLIGATOIRE

try:
    # Initialize embeddings with optimizations
    print("Initializing Ollama embeddings...")
    embeddings = OllamaEmbeddings(model=model_name)
    
    # Test embedding creation speed with a small sample
    print("Testing embedding speed...")
    test_start = time.time()
    test_doc = docs[0] if docs else Document(page_content="test")
    test_embedding = embeddings.embed_query(test_doc.page_content[:500])
    test_time = time.time() - test_start
    
    print(f"Single embedding test: {test_time:.2f}s")
    estimated_total = test_time * len(docs)
    print(f"Estimated total time: {estimated_total/60:.1f} minutes for {len(docs)} chunks")
    
    # Check if we should reduce chunk count for performance
    if len(docs) > 1000:
        print(f"⚠ Large chunk count ({len(docs)}) detected!")
        user_choice = input("Reduce chunks for faster processing? (y/n): ").lower().strip()
        
        if user_choice == 'y':
            # Keep only most important chunks
            important_docs = []
            
            # Keep all VPLE system info
            vple_docs = [d for d in docs if d.metadata.get("doc_type") == "VPLE"]
            important_docs.extend(vple_docs)
            
            # Keep diverse sample of CAPEC and MITRE
            capec_docs = [d for d in docs if d.metadata.get("doc_type") == "CAPEC"]
            mitre_docs = [d for d in docs if d.metadata.get("doc_type") == "MITRE"]
            
            # Take every Nth document to maintain diversity
            capec_step = max(1, len(capec_docs) // 200)  # Max 200 CAPEC chunks
            mitre_step = max(1, len(mitre_docs) // 200)  # Max 200 MITRE chunks
            
            important_docs.extend(capec_docs[::capec_step])
            important_docs.extend(mitre_docs[::mitre_step])
            
            docs = important_docs
            print(f"Reduced to {len(docs)} most important chunks")
    
    # Create the ChromaDB vector store DIRECTEMENT (plus simple et plus fiable)
    print(f"\nCreating embeddings for {len(docs)} chunks...")
    print("This may take several minutes - please be patient...")
    
    embedding_start = time.time()
    
    # Méthode DIRECTE - plus fiable que le batch processing
    print("Creating ChromaDB vector database...")
    
    vectorstore = Chroma.from_documents(
        documents=docs,
        embedding=embeddings,
        persist_directory="./vple_chroma_db"
    )
    
    total_time = time.time() - embedding_start
    
    print(f"✓ Vector store created successfully!")
    print(f"✓ Total time: {total_time/60:.1f} minutes")
    print(f"✓ Stored {len(docs)} chunks in ChromaDB")
    
    # Test the vector store with detailed search
    print(f"\nTesting vector store performance...")
    test_queries = [
        "web application attack techniques for Linux systems",
        "SQL injection attack patterns", 
        "privilege escalation techniques"
    ]
    
    for query in test_queries:
        search_start = time.time()
        similar_docs = vectorstore.similarity_search(query, k=3)
        search_time = time.time() - search_start
        
        print(f"Query: '{query}'")
        print(f"  Search time: {search_time:.3f}s")
        print(f"  Results: {len(similar_docs)} documents")
        
        if similar_docs:
            # Show diversity of results
            result_types = {}
            for doc in similar_docs:
                doc_type = doc.metadata.get("doc_type", "unknown")
                result_types[doc_type] = result_types.get(doc_type, 0) + 1
            
            print(f"  Result diversity: {result_types}")
            print(f"  Top result: {similar_docs[0].page_content[:100]}...")
        print()
    
    print(f"✓ Vector store is working efficiently!")
    
except Exception as e:
    print(f"✗ Vector store creation failed: {e}")
    print(f"Error details: {type(e).__name__}: {str(e)}")
    
    # Provide troubleshooting suggestions
    print("\nTroubleshooting suggestions:")
    print("1. Ensure Ollama service is running: ollama serve")
    print("2. Test Ollama manually: ollama run llama2:13b 'test'") 
    print("3. Check GPU memory: nvidia-smi")
    print("4. Restart Ollama service if needed")
    
    # Save progress anyway
    print("Saving documents for manual recovery...")
    import pickle
    with open("docs_backup.pkl", "wb") as f:
        pickle.dump(docs, f)
    print("✓ Documents saved to docs_backup.pkl")
    
    # Re-raise exception to stop execution
    raise e
