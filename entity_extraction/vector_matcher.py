from sentence_transformers import SentenceTransformer, util
import numpy as np

model = SentenceTransformer("paraphrase-multilingual-MiniLM-L12-v2")

def vector_match(input_text, candidates):
    input_vec = model.encode([input_text])
    candidate_vecs = model.encode(candidates)
    scores = util.cos_sim(input_vec, candidate_vecs)
    top_idx = scores.argmax()
    return candidates[top_idx], float(scores[0][top_idx])
