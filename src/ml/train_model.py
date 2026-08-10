import json
from pathlib import Path
import joblib, pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, roc_auc_score, confusion_matrix, classification_report
from sklearn.model_selection import train_test_split
from src.ml.feature_pipeline import FEATURE_NAMES, feature_frame

ROOT=Path(__file__).resolve().parents[2]; DATA=ROOT/'data'/'PhiUSIIL.csv'; MODELS=ROOT/'src'/'models'; MODEL=MODELS/'phishing_model.joblib'; EVAL=MODELS/'evaluation.json'
def train_and_evaluate():
    df=pd.read_csv(DATA, usecols=['URL','label']); y=(df['label']==0).astype(int) # PhiUSIIL: 0 phishing, 1 legitimate
    X=feature_frame(df['URL'].tolist())
    X_train_full,X_test,y_train_full,y_test=train_test_split(X,y,test_size=.15,random_state=42,stratify=y)
    X_train,X_valid,y_train,y_valid=train_test_split(X_train_full,y_train_full,test_size=.17647,random_state=42,stratify=y_train_full) # 70/15/15
    model=RandomForestClassifier(n_estimators=200,random_state=42,n_jobs=-1,max_depth=18,min_samples_leaf=2,class_weight='balanced')
    model.fit(X_train,y_train)
    # validation is recorded for reproducibility; no test-set tuning occurs
    valid_metrics={"accuracy":accuracy_score(y_valid,model.predict(X_valid))}
    pred=model.predict(X_test); probs=model.predict_proba(X_test)[:,list(model.classes_).index(1)]
    precision,recall,f1,_=precision_recall_fscore_support(y_test,pred,average='binary',zero_division=0)
    metrics={"dataset":DATA.name,"rows":int(len(df)),"features":list(FEATURE_NAMES),"label_mapping":{"0":"PHISHING","1":"LEGITIMATE"},"split":{"train":int(len(X_train)),"validation":int(len(X_valid)),"test":int(len(X_test))},"validation":valid_metrics,"test":{"accuracy":accuracy_score(y_test,pred),"precision":precision,"recall":recall,"f1":f1,"roc_auc":roc_auc_score(y_test,probs),"confusion_matrix":confusion_matrix(y_test,pred).tolist(),"false_negatives":int(((y_test==1)&(pred==0)).sum()),"classification_report":classification_report(y_test,pred,target_names=['LEGITIMATE','PHISHING'],output_dict=True,zero_division=0)}}
    MODELS.mkdir(exist_ok=True); joblib.dump({"model":model,"feature_names":list(FEATURE_NAMES),"metadata":metrics},MODEL); EVAL.write_text(json.dumps(metrics,indent=2))
    loaded=joblib.load(MODEL); assert loaded['model'].predict(feature_frame(['https://example.com'])).shape==(1,)
    print(json.dumps(metrics['test'],indent=2)); print(f'Saved {MODEL} ({MODEL.stat().st_size} bytes)'); return metrics
if __name__=='__main__': train_and_evaluate()
