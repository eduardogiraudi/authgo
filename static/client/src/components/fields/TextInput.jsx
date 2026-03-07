import { Form } from "react-bootstrap";

function TextInput({label, value, setValue, callback,placeholder,className="",error=""}){
    return <div className={className}>
        {label&&<label>{label}</label>}
        <Form.Control size="md" placeholder={placeholder} type="text"  value={value} onChange={(e) => setValue?setValue(e.target.value):callback(e)} className={error?'border border-danger':''} />
        <label className="text-danger">{error}</label>
    </div>
}
export default TextInput 