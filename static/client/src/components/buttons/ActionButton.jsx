import { Button } from "react-bootstrap"

function ActionButton({text, onClick,disabled=false}){
    return <Button variant="info" onClick={onClick} disabled={disabled}>{text}</Button>
}

export default ActionButton