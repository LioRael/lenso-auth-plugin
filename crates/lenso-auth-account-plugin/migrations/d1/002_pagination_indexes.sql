-- Support subject-filtered session pagination without a temporary sort.
CREATE INDEX auth_sessions_subject_session_idx ON auth_sessions(subject_id,session_id);
